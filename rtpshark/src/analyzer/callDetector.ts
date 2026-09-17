// Call Detector（call_detector.py + media_extractor.py 的 extract_call_parties 的 TS 移植）
// 把 RTP 流按端口对归组成媒体腿（conversation），按时间重叠 + 共享 IP 聚类成通话，
// 跨抓包按 SSRC 合并，再按信令对话框全局重绑拆分并发/交错通话，并评估每份抓包下
// 每通通话的完整性、FS 媒体转发判定（fs_relay）。
//
// 概念：
// - conversation（腿）：两个 IP:port 端点之间的双向媒体流，可能出现在多份抓包里
//   （按 SSRC 匹配）。一通电话通常有多条腿：FS 抓包里坐席腿 + 终端腿，每侧音视频各一条。
// - call：同一通电话的腿的集合，按时间重叠 + 共享 IP 聚类。经同一服务器的并发/交错
//   通话会并成一团，refineCalls 再按全部信令对话框全局重绑拆回各自通话。

import { AUDIO_PT, PT_NAMES } from './streamClassifier';
import type {
  CallInfo,
  Capture,
  RtpPacketRec,
  SipAddr,
  SdpCodecIdent,
  SdpInfo,
  SipEvent,
} from './types';

// ---------------------------------------------------------------------------
// 常量（与 Python 版一一对应）
// ---------------------------------------------------------------------------

// 端口对的不活跃间隔阈值：超过它把一个端口对拆成两个 conversation（后续通话的端口复用）。
// RTP 以 20ms 间隔流动，活跃通话不会有 30s 的包间隔。
export const PORT_REUSE_GAP_S = 30.0;
// 腿聚成同一通通话所需的时间重叠比例
export const CALL_OVERLAP_RATIO = 0.7;
// 媒体开始距抓包开始小于该值 → 怀疑缺开头
export const HEAD_EDGE_S = 3.0;
// 媒体结束距抓包结束小于该值 → 怀疑缺结尾
export const TAIL_EDGE_S = 3.0;
// 上行流首包 seq <= 该值视为「流从头被捕获」
export const SEQ_FRESH_MAX = 50;
// 腿的媒体结束/开始贴近对话框末条/首条消息这个距离内，才允许按对端 IP 绑定
// （无 SDP 宣告的对话框）。同一设备同时刻的多通电话里，只有与该对话框同呼
// 叫的那通腿会贴着它的 BYE/INVITE 结束或开始。对话框时间窗两端也按此距离
// 放宽（媒体在 BYE 前零点几秒停流、在 INVITE 后零点几秒才开始，都算相交）
export const DIALOG_BIND_PROX_S = 6.0;
// 半呼叫形状合并时，两个单元的媒体结束时间相差不得超过此值——同通话两侧
// 腿在挂断时同时停流。只看「时间重叠 + 端点 ≤2」会把共享同一设备 IP 的两
// 个不同通话的半边链式焊成一团
export const END_ALIGN_S = 3.0;

export const STATUS_LABELS: Record<string, string> = {
  complete: '完整',
  truncated_head: '缺开头（抓包时通话已在进行）',
  truncated_tail: '缺结尾（抓包结束时通话未结束）',
  truncated_both: '首尾都不完整',
};

// 同一条信令在多个抓包里时间差小于该值视为同一消息的副本（抓包时钟差 <1s，
// 但重传可以持续几十秒；同 CSeq+method+src+dst 按定义是同一事务的同一条消息）
export const SIP_DUP_WINDOW_S = 30.0;
// 同一条信令在多个抓包里都有副本时保留哪份：FS 端单一时钟、两侧腿都看得见，
// 时序自洽，最优先；其次终端（主叫端）；最后坐席端。混用不同机器时钟的消息
// 会因时钟偏差在时间线上排错序
export const ROLE_PRIORITY: Record<string, number> = { fs: 0, terminal: 1, seat: 2 };
// Call-ID 组落到某通通话的条件：组首条消息落在通话媒体时间范围该距离内
export const SIP_ASSOC_WINDOW_S = 15.0;

// 上传角色 → 展示名（跨抓包一致性提示用）
export const ROLE_DISPLAY: Record<string, string> = {
  seat: '被叫端（坐席）',
  fs: 'FS 端',
  terminal: '主叫端（终端）',
};

// ---------------------------------------------------------------------------
// 公共导出类型
// ---------------------------------------------------------------------------

/** 媒体端点 (ip, port) */
export type Ep = [string, number];

/** SIP 信令流程条目（阶梯图数据，Python call['sip_flow'] 的条目） */
export interface SipFlowItem {
  time: number;
  timeStr: string;
  method: string;
  cseqMethod: string;
  src: string;
  dst: string;
  // 所属腿（Call-ID）：前端按腿把协商行锚到该腿应答行之后
  callId: string | null;
  from: SipAddr;
  to: SipAddr;
  label: string;
  kind: SipFlowKind;
  // 带 SDP 的消息（offer/answer）标注其列出的编码，供前端把协商编码行插到应答行之后
  sdpCodecs: { audio?: string[]; video?: string[] } | null;
  // FS 在此消息里把对端媒体地址透传给了本端（媒体改道证据），供信令阶梯图标注
  mediaRedirect: { targets: string[]; ports: number[] } | null;
}

export type SipFlowKind = 'request' | 'provisional' | 'success' | 'error';

/** 媒体改道（SDP 透传）记录（Python call['media_redirects'] 条目） */
export interface MediaRedirect {
  time: number;
  timeStr: string;
  method: string;
  label: string;
  dst: string;
  callId: string | null;
  targets: string[];
  ports: number[];
}

/** 每条腿（Call-ID）的 SDP offer/answer 协商结果（Python call['leg_codecs'] 条目） */
export interface LegCodecInfo {
  role: 'caller' | 'callee';
  answered: boolean;
  audio: SdpCodecIdent[];
  video: SdpCodecIdent[];
}

/** 展示用协商编码（按腿拆开，Python call['negotiated_per_leg'] 条目） */
export interface NegotiatedLeg {
  audio: string[];
  video: string[];
  answered: boolean;
  callId: string | null;
}

/** 本通话会话里的 SDP 编码信息（Python call['sdp_codecs']） */
export interface SdpCodecs {
  audio: string[];
  video: string[];
  map: { audio: Record<string, string>; video: Record<string, string> };
}

/** FS 是否参与编解码的判定（Python _fs_media_verdict 输出） */
export interface FsMediaVerdict {
  verdict: 'transcode' | 'same' | 'bypass' | 'unknown';
  text: string;
}

/** 单台设备与 FS 之间某媒体类别的上下行实测 */
export interface FsRelayDeviceStats {
  pkts: number;
  spanS: number;
  lastStr: string | null;
}

export interface FsRelayDevice {
  ip: string;
  label: string;
  uplink: Record<'audio' | 'video', FsRelayDeviceStats>;
  downlink: Record<'audio' | 'video', FsRelayDeviceStats>;
}

export interface FsRelayRedirect {
  timeStr: string;
  label: string;
  dst: string;
  targets: string;
}

/** FS 媒体转发判定结果（Python _fs_relay_verdict 输出） */
export interface FsRelayVerdict {
  available: boolean;
  verdict: 'insufficient' | 'redirected' | 'no_relay' | 'partial_uplink' | 'relayed';
  headline: string;
  advice: string;
  redirects: FsRelayRedirect[];
  devices: FsRelayDevice[];
  notes: string[];
}

/** 每份抓包 × 每通通话的完整性判断（Python assess_call_completeness 输出） */
export interface CompletenessResult {
  status: string;
  perFile: Record<string, { status: string; reasons: string[] }>;
}

/** 通话的主叫/被叫 IP 与身份（Python media_extractor.extract_call_parties 输出）。
 * 信令缺失时对应 IP 为 null、身份为空 SipAddr。 */
export interface CallParties {
  callerIp: string | null;
  callerIdent: SipAddr;
  answererIp: string | null;
  answererIdent: SipAddr;
}

/** 跨抓包一致性检查的角色条目 */
export interface ConsistencyRoleItem {
  role: string;
  display: string;
  overall: { start?: string; end?: string; count: number };
  calls: { label: string; start: string; end: string }[];
}

/** 跨抓包一致性检查结果（Python check_capture_consistency 输出；null 表示一致） */
export interface CaptureConsistencyResult {
  kind: 'p2p' | 'mismatch';
  message: string;
  roles: ConsistencyRoleItem[];
  pairs: { a: string; b: string }[];
}

// ---------------------------------------------------------------------------
// 内部类型
// ---------------------------------------------------------------------------

/** 一条 SSRC 流在某个端口对 conversation 内的汇总 */
export interface ConvStream {
  pt: number;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  firstSeq: number;
  firstSeqByFile: Record<string, number>;
  count: number;
  start: number;
  end: number;
}

/** 媒体腿：两个 IP:port 端点之间的双向媒体流（方向合并），可跨抓包合并 */
export interface Conversation {
  endpoints: [Ep, Ep];
  ips: Set<string>;
  start: number;
  end: number;
  duration: number;
  streams: Map<number, ConvStream>;
  ssrcSet: Set<number>;
  files: Set<string>;
  perFileTime: Record<string, [number, number]>;
}

/** build_sip_flows 内部使用的信令事件（含来源抓包角色） */
export interface InternalSipEvent {
  time: number;
  method: string;
  reason: string;
  callId: string;
  cseq: number | null;
  cseqMethod: string;
  from: SipAddr;
  to: SipAddr;
  sdp: SdpInfo;
  src: string;
  dst: string;
  file: string;
}

/** 检测过程中的通话对象（腿集合 + 信令关联结果），最终转成 CallInfo */
export interface InternalCall {
  legs: Conversation[];
  start: number;
  end: number;
  duration: number;
  ssrcs: Set<number>;
  files: Set<string>;
  sipCallIds: Set<string>;
  sipFlow: SipFlowItem[];
  answerTime: number | null;
  byeTime: number | null;
  negotiatedCodecs: { audio: string[]; video: string[] };
  negotiatedPerLeg: Record<string, NegotiatedLeg>;
  legCodecs: Record<string, LegCodecInfo>;
  sdpEndpoints: Set<string>;
  sdpEndpointsByCid: Record<string, Set<string>>;
  sdpDialogRanges: Record<string, [number, number]>;
  sipPeersByCid: Record<string, Set<string>>;
  sdpCodecs: SdpCodecs;
  sdpAnswered: boolean;
  mediaRedirects: MediaRedirect[];
}

/** assess_call_completeness 用到的每份抓包信息 */
export interface CallFileInfo {
  captureStart: number | null;
  captureEnd: number | null;
  sipEvents: SipEvent[];
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/** 遍历 PacketMap 里的全部 (ssrc, seq, 记录) */
function* iterPacketRecords(packets: Capture['packets']): Generator<[number, number, RtpPacketRec]> {
  for (const [ssrc, bySeq] of packets) {
    for (const [seq, v] of bySeq) {
      yield [ssrc, seq, v];
    }
  }
}

function epKey(ip: string, port: number): string {
  return `${ip}|${port}`;
}

function epParse(key: string): Ep {
  const idx = key.lastIndexOf('|');
  return [key.slice(0, idx), Number(key.slice(idx + 1))];
}

/** Python 元组排序口径：先比 IP 字符串，再比端口数值 */
function epLess(a: Ep, b: Ep): number {
  if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
  return a[1] - b[1];
}

function setsIntersect<T>(a: Set<T>, b: Set<T>): boolean {
  const [small, big] = a.size <= b.size ? [a, b] : [b, a];
  for (const v of small) if (big.has(v)) return true;
  return false;
}

function setUnionSize<T>(a: Set<T>, b: Set<T>): number {
  const u = new Set(a);
  for (const v of b) u.add(v);
  return u.size;
}

function setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

function tupleLess(a: [number, number, number, number], b: [number, number, number, number]): boolean {
  for (let i = 0; i < 4; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

/** Python datetime.fromtimestamp(t).strftime('%H:%M:%S')（本地时区） */
export function fmtTime(t: number): string {
  const d = new Date(t * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function round1(x: number): number {
  return Math.round(x * 10) / 10;
}

const EMPTY_ADDR: SipAddr = { name: '', user: '', host: '' };

/** SIP From/To 头的可读称呼：'张三（1002）' / '1002' / 显示名。
 * 身份串按抓包原文展示，不做 base64 解码——平台分机号本身可能就是这种
 * 串，解码反而得到错误内容。话机自报的超长无空格单 token（From 的显示
 * 名与 user 常是同一串）没有可读性，不采用——端点由展示层以 IP 标注。 */
export function identLabel(ident: Partial<SipAddr> | null | undefined): string {
  if (!ident) return '';
  const name = (ident.name ?? '').trim();
  const user = (ident.user ?? '').trim();
  let label: string;
  if (name && user && name !== user && !name.includes(user)) {
    label = `${name}（${user}）`;
  } else {
    label = name || user;
  }
  if (label.length > 20 && !label.includes(' ')) return '';
  return label;
}

/** 消息类别（前端着色用） */
export function sipKind(method: string): SipFlowKind {
  if (['INVITE', 'ACK', 'BYE', 'CANCEL', 'UPDATE', 'PRACK'].includes(method)) return 'request';
  if (/^\d+$/.test(method)) {
    const code = parseInt(method, 10);
    if (code < 200) return 'provisional';
    if (code < 300) return 'success';
  }
  return 'error';
}

// ---------------------------------------------------------------------------
// build_conversations：单份抓包 → 媒体腿
// ---------------------------------------------------------------------------

/** 把一份抓包的 RTP 包归组成双向媒体腿（conversation）。
 * conversation 以端点对（双向合并）标识，并按长不活跃间隔拆分（端口被后续
 * 通话复用）。 */
export function buildConversations(capture: Capture, role: string): Conversation[] {
  type Ev = [number, number, number, number, string, number, string, number]; // t, ssrc, seq, pt, srcIp, sport, dstIp, dport
  const perKey = new Map<string, { key: [Ep, Ep]; events: Ev[] }>();
  for (const [ssrc, seq, v] of iterPacketRecords(capture.packets)) {
    const a: Ep = [v.srcIp, v.srcPort];
    const b: Ep = [v.dstIp, v.dstPort];
    const key: [Ep, Ep] = epLess(a, b) <= 0 ? [a, b] : [b, a];
    const ks = `${key[0][0]}|${key[0][1]}|${key[1][0]}|${key[1][1]}`;
    let entry = perKey.get(ks);
    if (!entry) {
      entry = { key, events: [] };
      perKey.set(ks, entry);
    }
    entry.events.push([v.time, ssrc, seq, v.pt, v.srcIp, v.srcPort, v.dstIp, v.dstPort]);
  }

  const conversations: Conversation[] = [];
  for (const { key, events } of perKey.values()) {
    events.sort((x, y) => x[0] - y[0]);
    // 按不活跃间隔拆段：复用该端口对的新通话从新的一段开始（新 SSRC）
    const segments: Ev[][] = [];
    for (const ev of events) {
      const last = segments[segments.length - 1];
      if (!last || ev[0] - last[last.length - 1][0] > PORT_REUSE_GAP_S) {
        segments.push([]);
      }
      segments[segments.length - 1].push(ev);
    }

    for (const seg of segments) {
      const streams = new Map<number, ConvStream>();
      for (const [t, ssrc, seq, pt, srcIp, sport, dstIp, dport] of seg) {
        let s = streams.get(ssrc);
        if (!s) {
          s = {
            pt,
            srcIp,
            srcPort: sport,
            dstIp,
            dstPort: dport,
            firstSeq: seq,
            firstSeqByFile: { [role]: seq },
            count: 0,
            start: t,
            end: t,
          };
          streams.set(ssrc, s);
        }
        s.count += 1;
        s.start = Math.min(s.start, t);
        s.end = Math.max(s.end, t);
      }

      const segStart = seg[0][0];
      const segEnd = seg[seg.length - 1][0];
      conversations.push({
        endpoints: [key[0], key[1]],
        ips: new Set([key[0][0], key[1][0]]),
        start: segStart,
        end: segEnd,
        duration: segEnd - segStart,
        streams,
        ssrcSet: new Set(streams.keys()),
        files: new Set([role]),
        perFileTime: { [role]: [segStart, segEnd] },
      });
    }
  }
  return conversations;
}

// ---------------------------------------------------------------------------
// merge_conversations：跨抓包按 SSRC 合并
// ---------------------------------------------------------------------------

function cloneConv(conv: Conversation): Conversation {
  const streams = new Map<number, ConvStream>();
  for (const [ssrc, st] of conv.streams) {
    streams.set(ssrc, { ...st, firstSeqByFile: { ...st.firstSeqByFile } });
  }
  return {
    endpoints: [conv.endpoints[0], conv.endpoints[1]],
    ips: new Set(conv.ips),
    start: conv.start,
    end: conv.end,
    duration: conv.duration,
    streams,
    ssrcSet: new Set(conv.ssrcSet),
    files: new Set(conv.files),
    perFileTime: Object.fromEntries(Object.entries(conv.perFileTime).map(([r, t]) => [r, [t[0], t[1]] as [number, number]])),
  };
}

/** 合并不同抓包文件里共享 SSRC 的 conversation。
 * 同一条媒体流经过的每个抓包点 SSRC 相同，所以共享 SSRC 意味着同一条腿被
 * 看到了两次。 */
export function mergeConversations(allConvs: Conversation[]): Conversation[] {
  const merged: Conversation[] = [];
  for (const conv of [...allConvs].sort((a, b) => a.start - b.start)) {
    const target = merged.find((m) => setsIntersect(m.ssrcSet, conv.ssrcSet));
    if (!target) {
      merged.push(cloneConv(conv));
      continue;
    }
    for (const f of conv.files) target.files.add(f);
    target.start = Math.min(target.start, conv.start);
    target.end = Math.max(target.end, conv.end);
    target.duration = target.end - target.start;
    for (const [role, [s, e]] of Object.entries(conv.perFileTime)) {
      const prev = target.perFileTime[role];
      target.perFileTime[role] = prev ? [Math.min(prev[0], s), Math.max(prev[1], e)] : [s, e];
    }
    for (const [ssrc, st] of conv.streams) {
      const ts = target.streams.get(ssrc);
      if (ts) {
        ts.count += st.count;
        ts.start = Math.min(ts.start, st.start);
        ts.end = Math.max(ts.end, st.end);
        Object.assign(ts.firstSeqByFile, st.firstSeqByFile);
      } else {
        target.streams.set(ssrc, { ...st, firstSeqByFile: { ...st.firstSeqByFile } });
      }
    }
    for (const ssrc of conv.ssrcSet) target.ssrcSet.add(ssrc);
  }
  return merged;
}

// ---------------------------------------------------------------------------
// group_calls：腿聚类成通话
// ---------------------------------------------------------------------------

/** 把 conversation 聚类成通话（时间重叠强 + 共享至少一个 IP 即同通话）。
 * 对端腿共享服务器 IP；同侧音视频腿共享端点 IP。先后通话不重叠所以分开；
 * 共享服务器 IP 的并发通话在此被并起，refineCalls 再用各自信令拆开。 */
export function groupCalls(conversations: Conversation[]): InternalCall[] {
  const n = conversations.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (i: number): number => {
    while (parent[i] !== i) {
      parent[i] = parent[parent[i]];
      i = parent[i];
    }
    return i;
  };
  const union = (i: number, j: number) => {
    const ri = find(i);
    const rj = find(j);
    if (ri !== rj) parent[rj] = ri;
  };

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const a = conversations[i];
      const b = conversations[j];
      if (setsIntersect(a.ssrcSet, b.ssrcSet)) {
        union(i, j);
        continue;
      }
      if (!setsIntersect(a.ips, b.ips)) continue;
      const overlap = Math.max(0, Math.min(a.end, b.end) - Math.max(a.start, b.start));
      if (overlap > CALL_OVERLAP_RATIO * Math.max(Math.min(a.duration, b.duration), 1e-9)) {
        union(i, j);
      }
    }
  }

  const groups = new Map<number, Conversation[]>();
  for (let i = 0; i < n; i++) {
    const r = find(i);
    const arr = groups.get(r);
    if (arr) arr.push(conversations[i]);
    else groups.set(r, [conversations[i]]);
  }

  const calls: InternalCall[] = [];
  for (const legs of groups.values()) {
    calls.push(makeCall(legs));
  }
  calls.sort((a, b) => a.start - b.start);
  return calls;
}

/** 腿集合变动后重算通话的时间范围 / SSRC / 抓包文件集合 */
export function rebuildCall(call: InternalCall): void {
  const legs = call.legs;
  if (!legs.length) {
    call.start = 0;
    call.end = 0;
    call.duration = 0;
    call.ssrcs = new Set();
    call.files = new Set();
    return;
  }
  call.start = Math.min(...legs.map((l) => l.start));
  call.end = Math.max(...legs.map((l) => l.end));
  call.duration = call.end - call.start;
  call.ssrcs = new Set(legs.flatMap((l) => [...l.ssrcSet]));
  call.files = new Set(legs.flatMap((l) => [...l.files]));
}

/** 用一组腿构造与 groupCalls 输出同构的通话对象 */
export function makeCall(legs: Conversation[]): InternalCall {
  const call: InternalCall = {
    legs: [...legs],
    start: 0,
    end: 0,
    duration: 0,
    ssrcs: new Set(),
    files: new Set(),
    sipCallIds: new Set(),
    sipFlow: [],
    answerTime: null,
    byeTime: null,
    negotiatedCodecs: { audio: [], video: [] },
    negotiatedPerLeg: {},
    legCodecs: {},
    sdpEndpoints: new Set(),
    sdpEndpointsByCid: {},
    sdpDialogRanges: {},
    sipPeersByCid: {},
    sdpCodecs: { audio: [], video: [], map: { audio: {}, video: {} } },
    sdpAnswered: false,
    mediaRedirects: [],
  };
  rebuildCall(call);
  return call;
}

function legsTimeOverlap(legsA: Conversation[], legsB: Conversation[]): number {
  let best = 0;
  for (const a of legsA) {
    for (const b of legsB) {
      const ov = Math.min(a.end, b.end) - Math.max(a.start, b.start);
      if (ov > best) best = ov;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// assess_call_completeness：每抓包 × 每通话的完整性判断
// ---------------------------------------------------------------------------

/** 按通话出现的每份抓包评估完整性。
 * file_info: {role: {captureStart, captureEnd, sipEvents}}。
 * 返回 {status: 总体, perFile: {role: {status, reasons}}}。 */
export function assessCallCompleteness(
  call: InternalCall,
  fileInfo: Record<string, CallFileInfo>,
  serverIp: string | null,
): CompletenessResult {
  const perFile: Record<string, { status: string; reasons: string[] }> = {};
  for (const role of [...call.files].sort()) {
    const fi = fileInfo[role];
    if (!fi || !fi.captureStart) continue;
    const capStart = fi.captureStart;
    const capEnd = fi.captureEnd ?? capStart;
    const sipEvents = fi.sipEvents;
    // 本文件里看到的通话时间范围
    const ranges = call.legs
      .filter((l) => role in l.perFileTime)
      .map((l) => l.perFileTime[role]);
    const cStart = Math.min(...ranges.map((r) => r[0]));
    const cEnd = Math.max(...ranges.map((r) => r[1]));

    const reasons: string[] = [];

    // 只信本通话自己的信令（按 Call-ID）；没有时退回媒体区间附近的任意 INVITE/BYE
    const callIds = call.sipCallIds.size > 0 ? call.sipCallIds : null;

    // --- 开头 ---
    let headTruncated = false;
    const invites = sipEvents.filter(
      (e) => e.method === 'INVITE' && e.time <= cStart + 1.0 && (!callIds || callIds.has(e.callId)),
    );
    if (invites.length) {
      reasons.push(`INVITE ${fmtTime(invites[0].time)} 早于媒体开始，通话开头已抓到`);
    } else {
      // 上行流：起自端点（src != 服务器）。只判断通话媒体开始附近已在流的
      // 流：通话中段才出现的新流（如 re-INVITE 后的新 SSRC）的首包 seq 说明
      // 不了通话开头是否被抓到。
      const uplinkSeqs: [number, number][] = [];
      for (const leg of call.legs) {
        if (!(role in leg.perFileTime)) continue;
        for (const st of leg.streams.values()) {
          if (serverIp && st.srcIp !== serverIp && role in st.firstSeqByFile) {
            uplinkSeqs.push([st.start, st.firstSeqByFile[role]]);
          }
        }
      }
      const early = uplinkSeqs.filter(([start]) => start <= cStart + HEAD_EDGE_S).map(([, seq]) => seq);
      if (early.length && Math.max(...early) <= SEQ_FRESH_MAX) {
        reasons.push(`上行流首包 seq=${Math.min(...early)}，媒体流从头被捕获`);
      } else if (early.length) {
        headTruncated = true;
        const mn = Math.min(...early);
        const mx = Math.max(...early);
        const seqSpan = mn === mx ? String(mn) : `${mn}~${mx}`;
        reasons.push(`上行流首包 seq=${seqSpan}（明显非零，流已进行一段时间）`);
      } else if (cStart - capStart < HEAD_EDGE_S) {
        headTruncated = true;
        reasons.push(`通话开始距抓包开始仅 ${(cStart - capStart).toFixed(1)}s（抓包时通话已在进行）`);
      }
    }

    // --- 结尾 ---
    let tailTruncated = false;
    const byes = sipEvents.filter(
      (e) => e.method === 'BYE' && e.time >= cEnd - 1.0 && (!callIds || callIds.has(e.callId)),
    );
    if (byes.length) {
      reasons.push(`BYE ${fmtTime(byes[byes.length - 1].time)} 晚于媒体结束，通话挂断已抓到`);
    } else {
      const tailGap = capEnd - cEnd;
      if (tailGap < TAIL_EDGE_S) {
        tailTruncated = true;
        reasons.push(`通话结束距抓包结束仅 ${tailGap.toFixed(1)}s（抓包结束时通话可能仍在进行）`);
      } else {
        reasons.push(`媒体结束后抓包又持续 ${tailGap.toFixed(1)}s，通话自然结束`);
      }
    }

    let status: string;
    if (headTruncated && tailTruncated) status = 'truncated_both';
    else if (headTruncated) status = 'truncated_head';
    else if (tailTruncated) status = 'truncated_tail';
    else status = 'complete';

    perFile[role] = { status, reasons };
  }

  // 总体 = 各文件中最差状态
  const order: Record<string, number> = {
    complete: 0,
    truncated_head: 1,
    truncated_tail: 1,
    truncated_both: 2,
  };
  let overall = 'complete';
  for (const pf of Object.values(perFile)) {
    if (order[pf.status] > order[overall]) overall = pf.status;
  }
  return { status: overall, perFile };
}

// ---------------------------------------------------------------------------
// build_sip_flows：信令去重、按 Call-ID 关联到通话
// ---------------------------------------------------------------------------

/** 给每通检测出的通话挂上去重后的 SIP 信令流程（就地修改）。
 * 信令消息按 Call-ID 分组；每组挂到媒体时间范围与其时间跨度最优重叠的那一
 * 通（窗口 + 最大重叠），背靠背的同端点通话不会互串信令。同时设置
 * call.sipCallIds（完整性评估只信本通话自己的 INVITE/BYE）与
 * call.answerTime / call.byeTime（接通后媒体窗口）。 */
export function buildSipFlows(
  calls: InternalCall[],
  captures: Record<string, Capture>,
  serverIp: string | null,
): void {
  const allEvents: InternalSipEvent[] = [];
  for (const [role, rd] of Object.entries(captures)) {
    for (const ev of rd.sipEvents ?? []) {
      allEvents.push({
        time: ev.time,
        method: ev.method,
        reason: ev.reason,
        callId: ev.callId,
        cseq: ev.cseq,
        cseqMethod: ev.cseqMethod,
        from: ev.from,
        to: ev.to,
        sdp: ev.sdp,
        src: ev.src,
        dst: ev.dst,
        file: role,
      });
    }
  }
  if (!allEvents.length) {
    for (const c of calls) {
      c.sipFlow = [];
      c.answerTime = null;
      c.byeTime = null;
      c.negotiatedCodecs = { audio: [], video: [] };
      c.negotiatedPerLeg = {};
      c.legCodecs = {};
      c.sdpEndpoints = new Set();
      c.sdpEndpointsByCid = {};
      c.sdpDialogRanges = {};
      c.sipPeersByCid = {};
      c.mediaRedirects = [];
    }
    return;
  }

  allEvents.sort((a, b) => a.time - b.time);
  const deduped: InternalSipEvent[] = [];
  for (const ev of allEvents) {
    let dupIdx: number | null = null;
    for (let i = deduped.length - 1; i >= 0; i--) {
      const seen = deduped[i];
      if (ev.time - seen.time > SIP_DUP_WINDOW_S) break;
      // 同 CSeq 号 => 同一消息的重传（在其他抓包点见过或线上重复）。不同
      // CSeq 是新事务（如带鉴权凭据重发的 INVITE）。
      if (
        ev.callId === seen.callId &&
        ev.method === seen.method &&
        ev.cseq === seen.cseq &&
        ev.src === seen.src &&
        ev.dst === seen.dst
      ) {
        dupIdx = i;
        break;
      }
    }
    if (dupIdx === null) {
      deduped.push(ev);
    } else if ((ROLE_PRIORITY[ev.file] ?? 9) < (ROLE_PRIORITY[deduped[dupIdx].file] ?? 9)) {
      // 同一条消息的多抓包副本：换成本次上传里优先级更高的那份，
      // 保证整条时间线出自同一台机器的时钟
      deduped[dupIdx] = ev;
    }
  }
  deduped.sort((a, b) => a.time - b.time);

  // 剩余消息按 Call-ID 分组
  const byCallId = new Map<string, InternalSipEvent[]>();
  for (const ev of deduped) {
    const arr = byCallId.get(ev.callId);
    if (arr) arr.push(ev);
    else byCallId.set(ev.callId, [ev]);
  }

  // 每个 Call-ID 组恰好属于一通通话：在关联窗口覆盖组首条消息的通话里，
  // 优先选 SDP 宣告媒体端点命中该通话实际媒体腿最多的（时间重叠的并发通话
  // 各拿各的对话框），其次非服务器信令对端 IP 命中媒体端点最多的（无 SDP 的
  // 对话框没有可匹配的宣告端点），再次组跨度与通话媒体范围重叠最大（平手看
  // 组首条消息到媒体范围的距离）。
  const attach = new Map<string, number>();
  for (const [cid, evs] of byCallId) {
    const g0 = evs[0].time;
    const g1 = evs[evs.length - 1].time;
    const announced = new Set<string>();
    for (const e of evs) {
      for (const ep of e.sdp?.endpoints ?? []) {
        if (ep.addr && ep.port) announced.add(epKey(ep.addr, ep.port));
      }
    }
    const peers = new Set<string>();
    for (const e of evs) {
      for (const ip of [e.src, e.dst]) {
        if (ip && ip !== serverIp) peers.add(ip);
      }
    }
    let bestIdx: number | null = null;
    let bestKey: [number, number, number, number] | null = null;
    for (let idx = 0; idx < calls.length; idx++) {
      const call = calls[idx];
      const lo = call.start - SIP_ASSOC_WINDOW_S;
      const hi = call.end + SIP_ASSOC_WINDOW_S;
      if (!(lo <= g0 && g0 <= hi)) continue;
      const overlap = Math.max(0, Math.min(g1, call.end) - Math.max(g0, call.start));
      const dist = Math.max(0, call.start - g0) + Math.max(0, g0 - call.end);
      let hits = 0;
      if (announced.size) {
        const legPairs = new Set<string>();
        for (const leg of call.legs) {
          for (const [ip, p] of leg.endpoints) legPairs.add(epKey(ip, p));
        }
        for (const a of announced) if (legPairs.has(a)) hits += 1;
      }
      let peerHits = 0;
      if (peers.size) {
        const legIps = new Set<string>();
        for (const leg of call.legs) {
          for (const ip of leg.ips) legIps.add(ip);
        }
        if (serverIp) legIps.delete(serverIp);
        for (const p of peers) if (legIps.has(p)) peerHits += 1;
      }
      const key: [number, number, number, number] = [-hits, -peerHits, -overlap, dist];
      if (bestKey === null || tupleLess(key, bestKey)) {
        bestIdx = idx;
        bestKey = key;
      }
    }
    if (bestIdx !== null) attach.set(cid, bestIdx);
  }

  for (let idx = 0; idx < calls.length; idx++) {
    const call = calls[idx];
    const flow: InternalSipEvent[] = [];
    const cids = new Set<string>();
    for (const [cid, i] of attach) {
      if (i === idx) {
        cids.add(cid);
        const evs = byCallId.get(cid);
        if (evs) flow.push(...evs);
      }
    }
    flow.sort((a, b) => a.time - b.time);
    call.sipCallIds = cids;
    // 本通话信令里宣告的媒体端点（SDP c=/m= 行的 ip:port），按 Call-ID 分组：
    // 精确圈定本通话的 RTP 流，供 refineCalls 把误并入的其他通话腿剔除/
    // 拆分。B2BUA 一通电话的 A/B 腿是两个 Call-ID，分组保留这一结构
    const byCidEps: Record<string, Set<string>> = {};
    const byCidRange: Record<string, [number, number]> = {};
    const byCidPeers: Record<string, Set<string>> = {};
    for (const cid of cids) {
      const evs = byCallId.get(cid) ?? [];
      const eps = new Set<string>();
      const peers = new Set<string>();
      for (const e of evs) {
        for (const ep of e.sdp?.endpoints ?? []) {
          if (ep.addr && ep.port) eps.add(epKey(ep.addr, ep.port));
        }
        for (const ip of [e.src, e.dst]) {
          if (ip && ip !== serverIp) peers.add(ip);
        }
      }
      const times = evs.filter((e) => e.time != null).map((e) => e.time);
      if (eps.size) byCidEps[cid] = eps;
      if (times.length) byCidRange[cid] = [Math.min(...times), Math.max(...times)];
      if (peers.size) byCidPeers[cid] = peers;
    }
    call.sdpEndpointsByCid = byCidEps;
    // 每个 Call-ID 的信令时间范围：媒体只可能落在 INVITE 之后、BYE之前，
    // 供 refineCalls 的强匹配排除「端口复用」造成的跨通话误命中
    call.sdpDialogRanges = byCidRange;
    // 每个 Call-ID 的信令对端 IP（非服务器侧 src/dst）：无 SDP 宣告的对话
    // 框（如抓包前已建立、只剩 re-INVITE/BYE 的通话）靠它把媒体腿绑定到
    // 所属通话
    call.sipPeersByCid = byCidPeers;
    call.sdpEndpoints = new Set(Object.values(byCidEps).flatMap((s) => [...s]));
    // 本通话会话里的 SDP：rtpmap 列出的编码 + PT→编码名映射（用于把
    // RTP 流实际使用的动态 PT 解析成编码名）
    const sdpCodecs: SdpCodecs = { audio: [], video: [], map: { audio: {}, video: {} } };
    for (const cid of cids) {
      for (const e of byCallId.get(cid) ?? []) {
        const sdp = e.sdp;
        for (const kind of ['audio', 'video'] as const) {
          for (const name of sdp?.[kind] ?? []) {
            if (!sdpCodecs[kind].includes(name)) sdpCodecs[kind].push(name);
          }
          const m = sdp?.map?.[kind] ?? {};
          for (const [pt, name] of Object.entries(m)) {
            if (sdpCodecs.map[kind][pt] === undefined) sdpCodecs.map[kind][pt] = name;
          }
        }
      }
    }
    call.sdpCodecs = sdpCodecs;
    // 应答/挂断时刻（用于「接通后媒体」区间）：应答 = INVITE 事务的 200 OK，
    // 优先取被叫设备发出的（B2BUA 里它先于服务器发给主叫的 200 OK）；挂断 =
    // 本通话第一条 BYE
    let answers = flow
      .filter((e) => e.method === '200' && e.cseqMethod === 'INVITE')
      .map((e) => e.time);
    if (serverIp) {
      const fromDev = flow
        .filter((e) => e.method === '200' && e.cseqMethod === 'INVITE' && e.src !== serverIp)
        .map((e) => e.time);
      if (fromDev.length) answers = fromDev;
    }
    call.answerTime = answers.length ? Math.min(...answers) : null;
    const byesT = flow.filter((e) => e.method === 'BYE').map((e) => e.time);
    call.byeTime = byesT.length ? Math.min(...byesT) : null;

    // —— 每条腿（Call-ID）的 SDP offer/answer 配对 ——
    // B2BUA 一通电话两条腿各一个 Call-ID，两条腿的 INVITE 各自带 SDP（都
    // 是 offer），跨腿配对会把两条腿的 offer 错配成 offer/answer，所以按
    // Call-ID 分组后各自独立配对：每组第一条带编码名的 SDP 是 offer，其后
    // 第一条是 answer（183 早释应答或 200 OK；慢启动时 offer 在 200 OK、
    // answer 在 ACK）。FS 自产 INVITE 的 SDP 若解析不出编码名（audio/video
    // 均空）对"协商了什么"没有信息量，配对时跳过。
    // 腿角色：INVITE 发自服务器的是被叫腿（FS→被叫），发往服务器的是主叫
    // 腿；服务器 INVITE 不可见时退回「流程首条 INVITE 所在 Call-ID 是主
    // 叫腿」——B2BUA 的被叫腿 INVITE 必然晚于主叫腿。
    const firstInvCid = flow.find((e) => e.method === 'INVITE')?.callId ?? null;
    const legCodecs: Record<string, LegCodecInfo> = {};
    for (const cid of cids) {
      const evs = byCallId.get(cid) ?? [];
      const sdpMsgs = evs.filter(
        (e) => e.sdp && ((e.sdp.audio?.length ?? 0) > 0 || (e.sdp.video?.length ?? 0) > 0),
      );
      if (!sdpMsgs.length) continue;
      const { negotiated, answered } = negotiateLeg(sdpMsgs);
      const inv = evs.find((e) => e.method === 'INVITE') ?? null;
      let role: 'caller' | 'callee';
      if (!inv) role = 'callee'; // 无 INVITE 副本的对话框按被叫腿处理
      else if (serverIp && inv.src === serverIp) role = 'callee';
      else if (serverIp && inv.dst === serverIp) role = 'caller';
      else role = cid === firstInvCid ? 'caller' : 'callee';
      legCodecs[cid] = { role, answered, ...negotiated };
    }
    call.legCodecs = legCodecs;
    // 展示用协商编码按腿拆开（主叫侧/被叫侧各一份）：前端先分别摆出两
    // 条腿各协商定了什么编码，再接 fs_media 的转码判定——判定本身就是
    // 对比这两份结果，展示顺序与判定依据一致。每份带 answered 标志，
    // 只有 offer 没等到 answer 的腿如实标为"候选"。
    const negotiatedPerLeg: Record<string, NegotiatedLeg> = {};
    let shown: LegCodecInfo | null = null;
    for (const role of ['caller', 'callee'] as const) {
      const leg = pickLeg(legCodecs, role);
      if (!leg) continue;
      const legCid = Object.keys(legCodecs).find((cid) => legCodecs[cid] === leg) ?? null;
      const names: { audio: string[]; video: string[] } = { audio: [], video: [] };
      for (const kind of ['audio', 'video'] as const) {
        names[kind] = [...new Set(leg[kind].map((c) => c.name))];
      }
      // call_id 供前端把该腿的协商行锚到这条腿自己的应答消息行之后
      negotiatedPerLeg[role] = { ...names, answered: leg.answered, callId: legCid };
      if (!shown) shown = leg;
    }
    call.negotiatedPerLeg = negotiatedPerLeg;
    // 旧汇总字段：主叫腿协商结果（无主叫腿 SDP 时退回任一腿），保持
    // 向后兼容；两腿差异由 fs_media 判定单独给出
    const fallback = negotiatedPerLeg.caller ?? negotiatedPerLeg.callee ?? { audio: [], video: [] };
    call.negotiatedCodecs = { audio: [...fallback.audio], video: [...fallback.video] };
    call.sdpAnswered = shown ? shown.answered : false;

    // —— 媒体改道（bypass media / SDP 透传）检测 ——
    // FS 中转媒体时，它自己产出的 SDP 一律宣告 FS 的媒体地址；若 FS 发出
    // 的消息里宣告的媒体端点是通话中另一台设备的 ip:port，说明 FS 把另一
    // 条腿的 SDP 原样透传了出去——媒体被改道为端到端直连，此后不再经过
    // FS（实测上表现为各端在改道后停止向 FS 上行 RTP）
    const devIps = new Set<string>();
    for (const leg of call.legs) {
      for (const ip of leg.ips) devIps.add(ip);
    }
    if (serverIp) devIps.delete(serverIp);
    const flowRedirects = new Map<number, { targets: string[]; ports: number[] }>();
    for (let i = 0; i < flow.length; i++) {
      const e = flow[i];
      if (serverIp && e.src !== serverIp) continue;
      const hits = (e.sdp?.endpoints ?? []).filter((ep) => devIps.has(ep.addr));
      if (hits.length) {
        flowRedirects.set(i, {
          targets: [...new Set(hits.map((ep) => ep.addr))].sort(),
          ports: [...new Set(hits.filter((ep) => ep.port).map((ep) => ep.port))].sort((a, b) => a - b),
        });
      }
    }
    call.mediaRedirects = [...flowRedirects.entries()].map(([i, info]) => ({
      time: flow[i].time,
      timeStr: fmtTime(flow[i].time),
      method: flow[i].method,
      label: flow[i].method + (flow[i].reason ? ' ' + flow[i].reason : ''),
      dst: flow[i].dst,
      callId: flow[i].callId,
      ...info,
    }));

    call.sipFlow = flow.map((e, i) => ({
      time: e.time,
      timeStr: fmtTime(e.time),
      method: e.method,
      cseqMethod: e.cseqMethod,
      src: e.src,
      dst: e.dst,
      // 所属腿（Call-ID）：前端按腿把协商行锚到该腿应答行之后
      callId: e.callId,
      from: e.from,
      to: e.to,
      label: e.method + (e.reason ? ' ' + e.reason : ''),
      kind: sipKind(e.method),
      // 带 SDP 的消息（offer/answer）标注其列出的编码，供前端把协商
      // 编码行插到应答行之后
      sdpCodecs: e.sdp
        ? (Object.fromEntries(
            (['audio', 'video'] as const)
              .filter((k) => (e.sdp[k]?.length ?? 0) > 0)
              .map((k) => [k, e.sdp[k]]),
          ) as { audio?: string[]; video?: string[] })
        : null,
      // FS 在此消息里把对端媒体地址透传给了本端（媒体改道证据），供
      // 信令阶梯图在消息行上直接标注
      mediaRedirect: flowRedirects.get(i) ?? null,
    }));
  }
}

// ---------------------------------------------------------------------------
// SDP offer/answer 配对与编码对比
// ---------------------------------------------------------------------------

/** SDP 消息里某路媒体的编码身份列表（{'name', 'rate'}，m= 行顺序）。
 * 'full' 由 SDP 解析生成；手工构造/旧格式的 SDP 只有名字列表时回退——
 * 时钟率未知，两腿对比时按名字相等处理。 */
function sdpCodecIdents(sdp: SdpInfo, kind: 'audio' | 'video'): SdpCodecIdent[] {
  const full = sdp?.full?.[kind];
  if (full && full.length) return full.map((c) => ({ name: c.name, rate: c.rate }));
  return (sdp?.[kind] ?? []).map((n) => ({ name: n, rate: null }));
}

/** 两编码是否视为同一种：名字相同，且任一方未报时钟率或时钟率一致。
 * 时钟率不同（如 OPUS/48000 vs OPUS/16000）是不同的编码格式，FS 必须转码。 */
function codecMatch(a: SdpCodecIdent, b: SdpCodecIdent): boolean {
  if (a.name !== b.name) return false;
  const ra = a.rate;
  const rb = b.rate;
  return ra === null || rb === null || ra === rb;
}

/** 一个 Call-ID（= B2BUA 的一条腿）内的 offer/answer 配对。
 * 按时间顺序扫描该腿带 SDP 的消息，以信令事务（CSeq）为单位配对，取
 * **最后一轮完整配对**作为该腿的协商结果——407 鉴权重发、桥接 blink
 * re-INVITE、会话刷新 re-INVITE 都会重新协商编码，实际生效的是最后一轮：
 * - 带 SDP 的 INVITE 是 offer（其应答 1xx/2xx 的 CSeq 与之一致才算它的
 *   answer；200 OK 之后再配 183 会被覆盖，最终答案以最终应答为准）；
 * - 无 SDP 的 blink INVITE 之后，设备在 200 OK 里发 offer、FS 的 ACK 带
 *   answer（慢启动同理：offer 在 200 OK、answer 在 ACK）；
 * - FS 自产 INVITE 的 SDP 若解析不出编码名（audio/video 均空）对"协商了
 *   什么"没有信息量，调用方已过滤。
 * 协商结果 = 双方列出编码的交集（保持 offer 顺序）；交集为空以 answer 为
 * 准（应答方决定，含拒绝某路媒体）；无 answer 时只有候选，谈不上协商。 */
export function negotiateLeg(
  sdpMsgs: InternalSipEvent[],
): { negotiated: { audio: SdpCodecIdent[]; video: SdpCodecIdent[] }; answered: boolean } {
  let negotiated: { audio: SdpCodecIdent[]; video: SdpCodecIdent[] } | null = null;
  let answered = false;
  let pending: { sdp: SdpInfo; cseq: number | null } | null = null; // 待应答的 offer
  let lastCseq: number | null = null; // 最近一轮配对的 offer 事务号：同事务的最终应答覆盖早先的 183
  let lastOfferSdp: SdpInfo | null = null;
  for (const e of sdpMsgs) {
    const sdp = e.sdp;
    if (!((sdp.audio?.length ?? 0) > 0 || (sdp.video?.length ?? 0) > 0)) continue;
    if (e.method === 'INVITE') {
      pending = { sdp, cseq: e.cseq };
      continue;
    }
    if (/^\d+$/.test(e.method)) {
      if (pending !== null && e.cseq === pending.cseq) {
        negotiated = pairOfferAnswer(pending.sdp, sdp);
        answered = true;
        lastCseq = pending.cseq;
        lastOfferSdp = pending.sdp;
        pending = null;
      } else if (pending === null && e.cseq === lastCseq) {
        // 同一事务更晚的应答（183 早释 → 200 OK 最终应答）覆盖更新
        negotiated = pairOfferAnswer(lastOfferSdp as SdpInfo, sdp);
      } else if (pending === null) {
        // 无 SDP 的 blink re-INVITE 之后，应答方在 200 OK 里发 offer
        pending = { sdp, cseq: e.cseq };
      }
      continue;
    }
    if (e.method === 'ACK' && pending !== null && e.cseq === pending.cseq) {
      negotiated = pairOfferAnswer(pending.sdp, sdp);
      answered = true;
      lastCseq = pending.cseq;
      lastOfferSdp = pending.sdp;
      pending = null;
    }
  }
  if (negotiated === null && pending !== null) {
    // 只有 offer 没等到应答：如实给候选
    negotiated = pairOfferAnswer(pending.sdp, null);
    answered = false;
  }
  if (negotiated === null) negotiated = { audio: [], video: [] };
  return { negotiated, answered };
}

/** 一轮 offer/answer 的协商结果：交集（offer 顺序），空则以 answer 为准 */
function pairOfferAnswer(
  offer: SdpInfo,
  answer: SdpInfo | null,
): { audio: SdpCodecIdent[]; video: SdpCodecIdent[] } {
  const negotiated: { audio: SdpCodecIdent[]; video: SdpCodecIdent[] } = { audio: [], video: [] };
  for (const kind of ['audio', 'video'] as const) {
    const offered = sdpCodecIdents(offer, kind);
    if (answer === null) {
      negotiated[kind] = offered;
      continue;
    }
    const ans = sdpCodecIdents(answer, kind);
    const inter = offered.filter((c) => ans.some((a) => codecMatch(c, a)));
    negotiated[kind] = inter.length ? inter : ans;
  }
  return negotiated;
}

/** 取该角色、带编码数据的腿；有多条时（并发振铃的分叉目标各占一条被叫
 * 腿）优先真正应答的那条，分叉目标未应答的 offer 只代表候选。 */
export function pickLeg(
  legCodecs: Record<string, LegCodecInfo>,
  role: 'caller' | 'callee',
): LegCodecInfo | null {
  const cands = Object.values(legCodecs).filter(
    (l) => l.role === role && (l.audio.length > 0 || l.video.length > 0),
  );
  if (!cands.length) return null;
  const answered = cands.filter((l) => l.answered);
  return (answered.length ? answered : cands)[0];
}

function fmtIdent(c: SdpCodecIdent): string {
  return c.name + (c.rate ? `/${c.rate}` : '');
}

/** 对比两腿协商编码，判定 FS 是否参与转码。无可比数据返回 null。 */
export function compareLegCodecs(
  caller: LegCodecInfo,
  callee: LegCodecInfo,
): { verdict: 'transcode' | 'same'; text: string } | null {
  const diffParts: string[] = [];
  const sameParts: string[] = [];
  for (const kind of ['audio', 'video'] as const) {
    const la = caller[kind] ?? [];
    const lb = callee[kind] ?? [];
    if (!la.length || !lb.length) continue; // 该路媒体单侧无候选（被应答方拒绝或没抓到），跳过
    const common = la.filter((c) => lb.some((x) => codecMatch(c, x)));
    const label = kind === 'audio' ? '音频' : '视频';
    if (common.length) {
      sameParts.push(`${label} ${common.map((c) => fmtIdent(c)).join('/')}`);
    } else {
      diffParts.push(
        `${label}：主叫侧 ${la.map((c) => fmtIdent(c)).join('/')}，` +
          `被叫侧 ${lb.map((c) => fmtIdent(c)).join('/')}`,
      );
    }
  }
  if (!diffParts.length && !sameParts.length) return null;
  if (diffParts.length) {
    return {
      verdict: 'transcode',
      text: '两腿协商编码不同（' + diffParts.join('；') + '），FS 必然参与转码',
    };
  }
  return {
    verdict: 'same',
    text: '两腿协商编码相同（' + sameParts.join('；') + '），FS 无需转码',
  };
}

// ---------------------------------------------------------------------------
// 主叫/被叫识别
// ---------------------------------------------------------------------------

/** 从信令流程识别主叫/被叫 IP（口径与 extractCallParties 一致，只取 IP）：
 * 主叫 = 第一个非服务器侧 INVITE 的源（回退首个请求），被叫 = INVITE 事务
 * 200 OK 的非服务器发送方；未接通（CANCEL/486/480/487 收场）没有 200 OK
 * 时，被叫退而取信令里出现最多的非服务器对端。识别不出返回 null。 */
export function callPartyPair(
  flow: SipFlowItem[],
  serverIp: string | null,
): [string | null, string | null] {
  if (!flow.length) return [null, null];
  const inv =
    flow.find((m) => m.method === 'INVITE' && m.src !== serverIp) ??
    flow.find((m) => m.kind === 'request' || !/^\d+$/.test(m.method)) ??
    flow[0];
  const ok = flow.find(
    (m) => m.method === '200' && m.cseqMethod === 'INVITE' && m.src !== serverIp,
  );
  let callee = ok ? ok.src : null;
  if (callee === null) {
    const callerIp = inv ? inv.src : null;
    const peers = new Map<string, number>();
    for (const m of flow) {
      for (const ip of [m.src, m.dst]) {
        if (ip && ip !== serverIp && ip !== callerIp) peers.set(ip, (peers.get(ip) ?? 0) + 1);
      }
    }
    if (peers.size) {
      callee = [...peers.entries()].sort((a, b) => b[1] - a[1])[0][0];
    }
  }
  return [inv ? inv.src : null, callee];
}

/** 从一通通话的信令流程里识别主叫/被叫的 IP 与身份。
 * 判定口径与前端 SIP 阶梯图一致：
 * - 主叫 = 第一个非服务器侧发出的 INVITE 的源，身份取其 From 头（UAC
 *   自报身份）；
 * - 被叫 = INVITE 事务 200 OK 的非服务器发送方，身份取呼向它的 INVITE
 *   的 To 头——响应回显请求的 From，不能用作被叫身份。
 * 信令缺失时对应项为 null / 空 SipAddr。 */
export function extractCallParties(call: CallInfo, serverIp: string | null): CallParties {
  const flow = call.signaling ?? [];
  let inv =
    flow.find((m) => m.method === 'INVITE' && m.src !== serverIp) ??
    flow.find((m) => m.kind === 'request') ??
    (flow.length ? flow[0] : undefined);
  const callerIp = inv ? inv.src : null;
  const callerIdent = inv ? inv.from : EMPTY_ADDR;

  const ok = flow.find(
    (m) => m.method === '200' && m.cseqMethod === 'INVITE' && m.src !== serverIp,
  );
  let answererIp = ok ? ok.src : null;
  if (answererIp === null) {
    // 未接通的通话（CANCEL/486/480/487 收场）没有 INVITE 的 200 OK：被叫
    // 退而取信令里出现最多的非服务器对端（与前端阶梯图同口径），保证被
    // 叫侧标注不丢
    const peers = new Map<string, number>();
    for (const m of flow) {
      for (const ip of [m.src, m.dst]) {
        if (ip && ip !== serverIp && ip !== callerIp) peers.set(ip, (peers.get(ip) ?? 0) + 1);
      }
    }
    if (peers.size) {
      answererIp = [...peers.entries()].sort((a, b) => b[1] - a[1])[0][0];
    }
  }
  let answererIdent: SipAddr = EMPTY_ADDR;
  if (answererIp) {
    // 呼向被叫的 INVITE 的 To；抓不到时退回 200 OK 的 To（回显同一头）
    const hasLabel = (m: SipFlowItem) => identLabel(m.to) !== '';
    let invTo =
      flow.find((m) => m.method === 'INVITE' && m.dst === answererIp && hasLabel(m)) ??
      flow.find((m) => m.dst === answererIp && hasLabel(m)) ??
      null;
    answererIdent = (invTo ? invTo.to : null) ?? (ok ? ok.to : null) ?? EMPTY_ADDR;
  }
  return { callerIp, callerIdent, answererIp, answererIdent };
}

// ---------------------------------------------------------------------------
// refine_calls：按信令对话框全局重绑媒体腿，重建通话分组
// ---------------------------------------------------------------------------

interface DialogView {
  eps: Set<string>; // SDP 宣告 (ip,port)，epKey 编码
  range: [number, number] | null; // (首条, 末条) 信令时间
  peers: Set<string>; // 非服务器侧信令对端 IP 集
}

/** 汇总所有通话信令里的对话框（Call-ID）信息，形成全局视图。
 * 第一轮信令关联只是按时间窗口尽力而为，可能把多个对话框并进同一通，也
 * 可能漏掉归属；拆分必须面对全部对话框一次做完——逐通话拆分会把缺头/缺尾
 * 通话的残腿错并进时间重叠的其他通话（服务器侧抓包里截到多通进行中的通话
 * 时必然如此）。 */
export function dialogViews(calls: InternalCall[]): Record<string, DialogView> {
  const views: Record<string, DialogView> = {};
  for (const call of calls) {
    const epsBy = call.sdpEndpointsByCid ?? {};
    const ranges = call.sdpDialogRanges ?? {};
    const peersBy = call.sipPeersByCid ?? {};
    const cids = new Set<string>([
      ...Object.keys(epsBy),
      ...Object.keys(ranges),
      ...Object.keys(peersBy),
    ]);
    for (const cid of cids) {
      let v = views[cid];
      if (!v) {
        v = { eps: new Set(), range: null, peers: new Set() };
        views[cid] = v;
      }
      for (const ep of epsBy[cid] ?? []) v.eps.add(ep);
      for (const p of peersBy[cid] ?? []) v.peers.add(p);
      const rng = ranges[cid];
      if (rng) {
        const cur = v.range ?? rng;
        v.range = [Math.min(cur[0], rng[0]), Math.max(cur[1], rng[1])];
      }
    }
  }
  return views;
}

/** 按信令对话框与媒体腿的全局绑定关系重建通话分组。
 * groupCalls 以「时间重叠 + 共享 IP」聚类，经同一服务器的并发/交错通话会
 * 并成一通——媒体回放里随之混入其他通话的流（流条数超出单通话上限，出现
 * 既非主叫也非被叫的端点）。对话框与媒体腿的对应关系是全局事实，一次性重
 * 绑：
 * 1. 强绑定——腿的端点 (ip,port) 命中对话框的 SDP 宣告、且媒体时间与对话
 *    框相交（允许媒体早于对话框首条消息：抓包开始前已建立的通话只有
 *    re-INVITE/BYE 落在抓包里，媒体却从头就在）；先后两通电话复用媒体端
 *    口时靠时间相交排除跨通话误命中；
 * 2. 对端绑定——无 SDP 宣告的对话框（只剩 BYE/re-INVITE 的半截信令）按
 *    信令对端 IP 绑定未强绑定的腿：腿的非服务器 IP 命中对端、媒体与对话
 *    框相交，多候选取媒体结束/开始贴对话框末条/首条消息最近的（同一设备
 *    的并发通话里只有同呼叫的那通贴着它的 BYE 挂断）；唯一的腿×对话框组合
 *    直接绑定，不要求贴近；
 * 3. 共享对话框的腿聚成组件；组件两两按「媒体时间重叠 + 合并后非服务器
 *    端点 ≤2 + 媒体结束时间对齐」并成通话——B2BUA 一通电话两侧腿媒体并
 *    发、挂断时同时停流，且只涉及两个设备端点（半呼叫形状）；冒出第 3 个
 *    端点、或挂断时刻对不上（共享同一设备 IP 的另一通电话会同时并发）即
 *    另一通电话；
 * 4. 没绑上任何对话框的腿（RTCP 端口对、信令全缺的媒体）：非服务器 IP 与
 *    某组件相交且时间重叠的归入，否则按旧规则（时间重叠 + 共享 IP）自聚
 *    成无信令通话。
 * 之后 detectCalls 会重跑一次信令关联（SDP 端点命中 + 对端 IP 命中优先），
 * 让各通拿到自己的 Call-ID 流程。 */
export function refineCalls(calls: InternalCall[], serverIp: string | null): InternalCall[] {
  const views = dialogViews(calls);
  if (!calls.length || !Object.keys(views).length) return calls;

  const legs: Conversation[] = calls.flatMap((c) => c.legs);

  const devips = (leg: Conversation): Set<string> => {
    const ips = new Set(leg.ips);
    if (serverIp) ips.delete(serverIp);
    return ips;
  };

  const crosses = (leg: Conversation, rng: [number, number]): boolean => {
    // 对话框时间窗两端放宽：BYE 前媒体先停、INVITE 后媒体才起，都算相交
    return !(leg.start > rng[1] + DIALOG_BIND_PROX_S || rng[0] - DIALOG_BIND_PROX_S > leg.end);
  };

  // 1. 强绑定：SDP 宣告端点命中 + 媒体时间与对话框相交
  const bound = new Map<number, Set<string>>();
  for (let i = 0; i < legs.length; i++) {
    const leg = legs[i];
    const pairs = new Set<string>(leg.endpoints.map(([ip, p]) => epKey(ip, p)));
    const cids = new Set<string>();
    for (const [cid, v] of Object.entries(views)) {
      if (setsIntersect(v.eps, pairs) && (!v.range || crosses(leg, v.range))) cids.add(cid);
    }
    if (cids.size) bound.set(i, cids);
  }

  // 2. 对端绑定：无 SDP 宣告的对话框按信令对端 IP 绑定剩余腿
  const candCids = new Map<number, Set<string>>(); // 腿 -> 候选对话框集
  const candLegs = new Map<string, Set<number>>(); // 对话框 -> 候选腿集
  for (let i = 0; i < legs.length; i++) {
    if (bound.has(i)) continue;
    const dev = devips(legs[i]);
    if (!dev.size) continue;
    for (const [cid, v] of Object.entries(views)) {
      if (v.eps.size || !v.range || !v.peers.size) continue;
      if (setsIntersect(dev, v.peers) && crosses(legs[i], v.range)) {
        let s = candCids.get(i);
        if (!s) {
          s = new Set();
          candCids.set(i, s);
        }
        s.add(cid);
        let t = candLegs.get(cid);
        if (!t) {
          t = new Set();
          candLegs.set(cid, t);
        }
        t.add(i);
      }
    }
  }
  for (const [i, cids] of candCids) {
    const leg = legs[i];
    const first = [...cids][0];
    if (cids.size === 1 && candLegs.get(first)!.size === 1) {
      bound.set(i, new Set(cids)); // 唯一组合：不问远近
      continue;
    }
    let best: [number, string] | null = null;
    for (const cid of cids) {
      const rng = views[cid].range as [number, number];
      const d = Math.min(Math.abs(leg.end - rng[1]), Math.abs(leg.start - rng[0]));
      if (d <= DIALOG_BIND_PROX_S && (best === null || d < best[0])) best = [d, cid];
    }
    if (best) bound.set(i, new Set([best[1]]));
  }

  // 3. 共享对话框的腿聚成组件（并查集），再按半呼叫形状两两合并
  const parent = Array.from({ length: legs.length }, (_, i) => i);
  const find = (i: number): number => {
    while (parent[i] !== i) {
      parent[i] = parent[parent[i]];
      i = parent[i];
    }
    return i;
  };

  const byCid = new Map<string, number[]>();
  for (const [i, cids] of bound) {
    for (const cid of cids) {
      const arr = byCid.get(cid);
      if (arr) arr.push(i);
      else byCid.set(cid, [i]);
    }
  }
  for (const members of byCid.values()) {
    for (let k = 1; k < members.length; k++) {
      const ri = find(members[0]);
      const rj = find(members[k]);
      if (ri !== rj) parent[rj] = ri;
    }
  }

  const compMembers = new Map<number, number[]>();
  for (const i of bound.keys()) {
    const r = find(i);
    const arr = compMembers.get(r);
    if (arr) arr.push(i);
    else compMembers.set(r, [i]);
  }
  interface Unit {
    legs: Conversation[];
    cids: Set<string>;
  }
  const units: Unit[] = [...compMembers.values()].map((members) => ({
    legs: members.map((i) => legs[i]),
    cids: new Set<string>(members.flatMap((i) => [...(bound.get(i) as Set<string>)])),
  }));

  const unitDevips = (u: Unit): Set<string> => {
    const ips = new Set<string>();
    for (const leg of u.legs) {
      for (const ip of devips(leg)) ips.add(ip);
    }
    for (const cid of u.cids) {
      for (const ep of views[cid].eps) ips.add(epParse(ep)[0]);
    }
    if (serverIp) ips.delete(serverIp);
    return ips;
  };
  const unitEnd = (u: Unit): number => Math.max(...u.legs.map((leg) => leg.end));

  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < units.length && !changed; i++) {
      for (let j = i + 1; j < units.length; j++) {
        if (
          setUnionSize(unitDevips(units[i]), unitDevips(units[j])) > 2 ||
          Math.abs(unitEnd(units[i]) - unitEnd(units[j])) > END_ALIGN_S ||
          legsTimeOverlap(units[i].legs, units[j].legs) <= 0
        ) {
          continue;
        }
        for (const cid of units[j].cids) units[i].cids.add(cid);
        units[i].legs = units[i].legs.concat(units[j].legs);
        units.splice(j, 1);
        changed = true;
        break;
      }
    }
  }

  // 4. 未绑定任何对话框的腿：非服务器 IP 命中某组件且时间重叠的归入组件
  const orphans: Conversation[] = [];
  for (let i = 0; i < legs.length; i++) {
    if (bound.has(i)) continue;
    const leg = legs[i];
    const dev = devips(leg);
    let target: Unit | null = null;
    let bestOv = 0;
    for (const u of units) {
      if (!setsIntersect(dev, unitDevips(u))) continue;
      const ov = legsTimeOverlap(u.legs, [leg]);
      if (ov > bestOv) {
        target = u;
        bestOv = ov;
      }
    }
    if (target) target.legs.push(leg);
    else orphans.push(leg);
  }

  const result = units.map((u) => makeCall(u.legs));
  if (orphans.length) result.push(...groupCalls(orphans));
  result.sort((a, b) => a.start - b.start || a.end - b.end);
  return result;
}

// ---------------------------------------------------------------------------
// FS 媒体判定（fs_media / fs_relay）
// ---------------------------------------------------------------------------

/** 通话媒体是否完全不经服务器转发（点对点直连）。
 * 正常经服务器转发的通话，每条腿必有一端是服务器 IP；所有腿的端点都不含
 * 服务器 IP，说明媒体在两个端点之间直连（终端直拨坐席 / 旁路媒体）。 */
export function isDirectMedia(call: InternalCall, serverIp: string | null): boolean {
  if (!serverIp) return false;
  return call.legs.every((leg) => !leg.ips.has(serverIp));
}

/** 无（完整）腿 SDP 时的兜底：按媒体路径把通话的腿分到主叫/被叫两侧，
 * 收集每侧实际使用的音频编码名（RTP 流真实出现的 PT 反查：动态 PT 用全
 * 流程 SDP rtpmap，静态 PT 用内置表并去掉括号说明，保持与 SDP 名可互比）。
 * 腿的归侧依据非服务器端点 IP：只与主叫 IP 通信的腿是主叫侧，只与被叫 IP
 * 通信的是被叫侧；两端直连的腿（p2p）与识别不出的腿不归侧。主被叫 IP 缺
 * 一或重合（信令只见到单侧）时返回空，表示不可比。 */
export function legPtSides(
  call: InternalCall,
  serverIp: string | null,
): Partial<Record<'caller' | 'callee', Set<string>>> {
  const [callerIp, calleeIp] = callPartyPair(call.sipFlow, serverIp);
  if (!callerIp || !calleeIp || callerIp === calleeIp) return {};
  const sdpMap = call.sdpCodecs?.map ?? { audio: {}, video: {} };
  const sides: { caller: Set<string>; callee: Set<string> } = {
    caller: new Set(),
    callee: new Set(),
  };
  for (const leg of call.legs) {
    const others = new Set(leg.ips);
    if (serverIp) others.delete(serverIp);
    const side: 'caller' | 'callee' | null = setsEqual(others, new Set([callerIp]))
      ? 'caller'
      : setsEqual(others, new Set([calleeIp]))
        ? 'callee'
        : null;
    if (side === null) continue;
    for (const st of leg.streams.values()) {
      const name =
        sdpMap.audio?.[String(st.pt)] || PT_NAMES[st.pt]?.split(' (')[0] || '';
      if (name) sides[side].add(name);
    }
  }
  const out: Partial<Record<'caller' | 'callee', Set<string>>> = {};
  if (sides.caller.size) out.caller = sides.caller;
  if (sides.callee.size) out.callee = sides.callee;
  return out;
}

/** 判定「FS 参与编解码了吗」，供 SIP 流程展示。
 * - bypass：媒体不经 FS（点对点直连 / bypass media），FS 不在媒体路径，
 *   未参与编解码；
 * - transcode：两腿协商编码不同，FS 作为 B2BUA 必然解码再编码（转码）；
 * - same：两腿编码相同，FS 即使在媒体路径也没有编码格式转换发生（是否
 *   透传/重打包不影响该结论）；
 * - unknown：数据不足——只见到一条腿的协商编码、无 SDP 且 RTP PT 反查也
 *   不可比（如动态 PT 无 rtpmap）。
 * SDP 对比不可行时用每条腿实际使用的音频 PT 反查编码名兜底（结论标注
 * 推断来源）。媒体已被改道（SDP 透传）时 FS 不在媒体路径，转码问题随之
 * 无意义，直接给 bypass 结论。 */
export function fsMediaVerdict(
  call: InternalCall,
  isP2p: boolean,
  serverIp: string | null,
): FsMediaVerdict {
  if (isP2p) {
    return {
      verdict: 'bypass',
      text: '媒体在两端之间直连（点对点 / bypass media），FS 不在媒体路径，未参与编解码',
    };
  }
  const redirs = call.mediaRedirects ?? [];
  if (redirs.length) {
    const r0 = redirs[0];
    return {
      verdict: 'bypass',
      text: `FS 已在 ${r0.timeStr} 把媒体改道为端到端直连（SDP 透传），FS 不在媒体路径，未参与编解码`,
    };
  }
  const caller = pickLeg(call.legCodecs ?? {}, 'caller');
  const callee = pickLeg(call.legCodecs ?? {}, 'callee');
  if (caller && callee) {
    const res = compareLegCodecs(caller, callee);
    if (res) return res;
  }
  const sides = legPtSides(call, serverIp);
  if (sides.caller && sides.callee) {
    const a = [...sides.caller].sort();
    const b = [...sides.callee].sort();
    if (a.join('、') === b.join('、')) {
      return {
        verdict: 'same',
        text: `两腿实际使用的编码相同（${a.join('、')}），FS 无需转码（依 RTP 载荷类型推断）`,
      };
    }
    return {
      verdict: 'transcode',
      text: `主叫侧使用 ${a.join('、')}，被叫侧使用 ${b.join('、')}，FS 参与转码（依 RTP 载荷类型推断）`,
    };
  }
  return { verdict: 'unknown', text: '未能同时看到两条腿的协商编码或实际编码，无法判定' };
}

/** 收集各抓包解析出的流种类（{ssrc: 'audio'|'video'}）。
 * 动态 PT（96-127）按媒体种类独立分配（audio 96=OPUS 与 video 96=H264 可
 * 同号并存），媒体种类以解析阶段按 SDP 端口绑定/时钟率判定的 kind 为准。 */
export function streamKinds(captures: Record<string, Capture>): Map<number, 'audio' | 'video'> {
  const kinds = new Map<number, 'audio' | 'video'>();
  for (const rd of Object.values(captures)) {
    for (const [ssrcKey, info] of Object.entries(rd.streams ?? {})) {
      const kind = info?.kind;
      const ssrc = Number(ssrcKey);
      if ((kind === 'audio' || kind === 'video') && !kinds.has(ssrc)) kinds.set(ssrc, kind);
    }
  }
  return kinds;
}

/** 一条流的媒体种类：解析标注优先，静态 PT 表兜底。 */
export function ptKind(
  kinds: Map<number, 'audio' | 'video'>,
  ssrc: number,
  pt: number,
): 'audio' | 'video' | null {
  return (
    kinds.get(ssrc) ??
    (AUDIO_PT.has(pt) ? 'audio' : pt >= 96 && pt <= 127 ? 'video' : null)
  );
}

interface RelayAgg {
  pkts: number;
  first: number;
  last: number;
}

/** 判定这通通话的音视频流有没有经过 FS 转发，给出排查方向提示。
 * 实测判据是各设备与 FS 之间的 RTP 上/下行（腿内每条 SSRC 流方向恒定），
 * 信令判据是 SDP 透传改道（mediaRedirects）。结论按排查优先级组织：
 * 1. 中转问题优先——FS 改道直连（SDP 透传）、或两端都没有向 FS 上行 RTP，
 *    说明媒体没走 FS 中转，先查 FS 中转配置（bypass media / 媒体地址通告），
 *    不要先怀疑网络；
 * 2. 网络问题其次——只有部分端点/媒体有上行时（发了的和没发的混着），
 *    才往网络方向排查。
 * 返回 null 表示无需此判定（点对点直连通话已有专门提示，或无服务器 IP）。 */
export function fsRelayVerdict(
  call: InternalCall,
  captures: Record<string, Capture>,
  serverIp: string,
): FsRelayVerdict | null {
  if (!serverIp) return null;
  // 全部腿都不经过服务器：点对点直连，转发判定无意义（另有提示）
  if (!call.legs.some((leg) => leg.ips.has(serverIp))) return null;
  // 转发判定只能由服务器侧抓包下结论：别的抓包点看不到"是否发给了 FS"
  const hasServerCapture = Object.values(captures).some((rd) => rd.ips?.includes(serverIp));
  if (!hasServerCapture) {
    return {
      available: true,
      verdict: 'insufficient',
      headline: '没有 FS 侧抓包，无法判断媒体是否经过 FS 中转（需在 FS 上或其镜像口抓包）',
      advice: '',
      redirects: [],
      devices: [],
      notes: [],
    };
  }

  // 每台设备与 FS 之间按媒体类别的上下行实测
  const streamKindsMap = streamKinds(captures);
  const stats = new Map<string, { up: Map<string, RelayAgg>; down: Map<string, RelayAgg> }>();
  for (const leg of call.legs) {
    if (!leg.ips.has(serverIp)) continue;
    for (const [ssrc, st] of leg.streams) {
      let direction: 'up' | 'down';
      let dev: string;
      if (st.srcIp === serverIp) {
        direction = 'down';
        dev = st.dstIp;
      } else if (st.dstIp === serverIp) {
        direction = 'up';
        dev = st.srcIp;
      } else {
        continue;
      }
      const kind = ptKind(streamKindsMap, ssrc, st.pt);
      if (!kind) continue;
      let s = stats.get(dev);
      if (!s) {
        s = { up: new Map(), down: new Map() };
        stats.set(dev, s);
      }
      let agg = s[direction].get(kind);
      if (!agg) {
        agg = { pkts: 0, first: st.start, last: st.end };
        s[direction].set(kind, agg);
      }
      agg.pkts += st.count;
      agg.first = Math.min(agg.first, st.start);
      agg.last = Math.max(agg.last, st.end);
    }
  }

  // 期望参与转发的设备集：信令识别出的主叫/被叫，缺信令时退回媒体腿上
  // 与 FS 通信过的非服务器 IP
  const [callerIp, calleeIp] = callPartyPair(call.sipFlow, serverIp);
  let expected = [callerIp, calleeIp].filter((ip): ip is string => !!ip && ip !== serverIp);
  if (!expected.length) {
    expected = [
      ...new Set(
        call.legs
          .filter((leg) => leg.ips.has(serverIp))
          .flatMap((leg) => [...leg.ips]),
      ),
    ]
      .filter((ip) => ip !== serverIp)
      .sort();
  }

  const label = (ip: string): string => {
    if (ip === callerIp) return `主叫端 ${ip}`;
    if (ip === calleeIp) return `被叫端 ${ip}`;
    return `端点 ${ip}`;
  };

  const devStats = (m: Map<string, RelayAgg>, kind: 'audio' | 'video'): FsRelayDeviceStats => {
    const a = m.get(kind);
    return {
      pkts: a?.pkts ?? 0,
      spanS: round1(Math.max(0, (a?.last ?? 0) - (a?.first ?? 0))),
      lastStr: a ? fmtTime(a.last) : null,
    };
  };

  const devices: FsRelayDevice[] = expected.map((ip) => {
    const s = stats.get(ip) ?? { up: new Map<string, RelayAgg>(), down: new Map<string, RelayAgg>() };
    return {
      ip,
      label: label(ip),
      uplink: { audio: devStats(s.up, 'audio'), video: devStats(s.up, 'video') },
      downlink: { audio: devStats(s.down, 'audio'), video: devStats(s.down, 'video') },
    };
  });

  const redirs = call.mediaRedirects ?? [];
  const notes: string[] = [];
  const hasUp = (d: FsRelayDevice) => Object.values(d.uplink).some((v) => v.pkts > 0);
  const upDevs = devices.filter(hasUp);
  const noUpDevs = devices.filter((d) => !hasUp(d));

  let headline: string;
  let advice: string;
  if (redirs.length) {
    const r0 = redirs[0];
    const dstLabel = r0.dst !== serverIp ? label(r0.dst) : r0.dst;
    headline =
      `FS 在 ${r0.timeStr} 用 ${r0.label} 把媒体改道为端到端直连` +
      `（SDP 透传，向 ${dstLabel} 宣告 ${r0.targets.join('、')} 的媒体地址），` +
      '此后音视频流不再经过 FS 转发。';
    // 佐证：各端上行是否随改道一并停止（改道时刻 ±5 秒内停 = 服从了新
    // SDP，是干净的信令性停止，不是网络丢包的形态）
    const stopped: string[] = [];
    const kept: string[] = [];
    for (const d of upDevs) {
      const lasts: number[] = [];
      for (const [k, v] of Object.entries(d.uplink)) {
        if (v.pkts > 0 && v.lastStr) {
          const agg = stats.get(d.ip)?.up.get(k as 'audio' | 'video');
          if (agg) lasts.push(agg.last);
        }
      }
      if (lasts.length && lasts.every((t) => Math.abs(t - r0.time) <= 5.0)) {
        stopped.push(d.label);
      } else if (lasts.length) {
        kept.push(d.label);
      }
    }
    if (stopped.length) {
      notes.push(
        `${stopped.join('、')}的 RTP 上行在改道时刻即停止——各端服从了新 SDP，属干净的信令性停止，不是网络丢包`,
      );
    }
    if (kept.length) {
      notes.push(`${kept.join('、')}在改道后仍有上行（FS 侧仍在收部分媒体）`);
    }
    advice =
      '排查优先级：这是中转问题，不是网络问题。先确认 FS 的媒体旁路' +
      '配置（bypass_media / bypass_media_after_bridge 等）是否符合预期；' +
      '本抓包点看不到端到端直连的媒体，若要确认两端是否真正收到对方的' +
      '音视频，需在两端本地抓包验证。';
  } else if (!upDevs.length) {
    const names = devices.map((d) => d.label).join('、') || '两端';
    headline = `${names}都没有向 FS 发送任何 RTP——音视频流没有经过 FS 中转。`;
    advice =
      '排查优先级：两端都不往 FS 发媒体 → 优先排查中转问题：' +
      'FS 是否配置了 bypass media、信令里宣告的媒体地址是否指向 FS、' +
      '两端是否拿到了彼此地址在直连；确认后才是网络问题。';
  } else if (noUpDevs.length) {
    const sent = upDevs.map((d) => d.label).join('、');
    const missing = noUpDevs.map((d) => d.label).join('、');
    headline = `只有 ${sent} 向 FS 发送了媒体，${missing} 没有任何上行 RTP。`;
    advice =
      '排查优先级：一部分发了、一部分没发 → 这种情况才考虑网络问题：' +
      '先在未发送端本地抓包，确认它确实在发（排除终端自身不发），' +
      '再逐段检查链路、防火墙/NAT。';
  } else {
    headline = '各端都有上行、FS 也有下行——媒体确实经过 FS 中转。';
    advice = '';
  }
  // 下行来源核对：FS 的下行应能被对端的上行解释（转发包数 1:1）。
  // 对端没发过、或包数远小于下行，说明该下行不是转发——FS 本地媒体源
  // （彩铃/视频公告/MOH 等），这直接影响"FS 是否在转发"的结论。
  for (const d of devices) {
    const peer = devices.find((x) => x.ip !== d.ip) ?? null;
    if (!peer) continue;
    for (const [kind, kname] of [
      ['audio', '音频'],
      ['video', '视频'],
    ] as const) {
      const up = peer.uplink[kind];
      const down = d.downlink[kind];
      if (!down.pkts) {
        if (up.pkts) {
          notes.push(
            `FS 从未向 ${d.label} 下发${kname}` +
              `（0 包，而对端 ${peer.label} 上行过` +
              ` ${up.pkts} 包）——该方向未发生转发`,
          );
        }
        continue;
      }
      if (!up.pkts) {
        notes.push(
          `FS 向 ${d.label} 下发了 ${down.pkts} 包${kname}，` +
            `但 ${peer.label} 从未上行过${kname}——该下行并非` +
            '转发，应是 FS 本地媒体源（如彩铃/视频公告/MOH）',
        );
      } else if (down.spanS > 30 && down.pkts > up.pkts * 4) {
        notes.push(
          `FS 向 ${d.label} 下发${kname} ${down.pkts} 包` +
            `（覆盖约 ${down.spanS} 秒），而 ${peer.label}` +
            ` 上行仅 ${up.pkts} 包（约 ${up.spanS} 秒）——` +
            '下行主体并非来自对端的转发',
        );
      }
    }
  }

  return {
    available: true,
    verdict: redirs.length
      ? 'redirected'
      : !upDevs.length
        ? 'no_relay'
        : noUpDevs.length
          ? 'partial_uplink'
          : 'relayed',
    headline,
    advice,
    redirects: redirs.map((r) => ({
      timeStr: r.timeStr,
      label: r.label,
      dst: r.dst !== serverIp ? label(r.dst) : r.dst,
      targets: r.targets.join('、'),
    })),
    devices,
    notes,
  };
}

// ---------------------------------------------------------------------------
// detect_calls：主入口
// ---------------------------------------------------------------------------

/** 跨全部上传抓包检测通话。
 * 返回按开始时间排序的 CallInfo 列表。 */
export function detectCalls(
  captures: Record<string, Capture>,
  serverIp: string | null,
): CallInfo[] {
  const allConvs: Conversation[] = [];
  const fileInfo: Record<string, CallFileInfo> = {};
  for (const [role, rd] of Object.entries(captures)) {
    allConvs.push(...buildConversations(rd, role));
    fileInfo[role] = {
      captureStart: rd.captureStart,
      captureEnd: rd.captureEnd,
      sipEvents: rd.sipEvents ?? [],
    };
  }

  const merged = mergeConversations(allConvs);
  let rawCalls = groupCalls(merged);
  buildSipFlows(rawCalls, captures, serverIp);
  // 并发/交错通话会被时间重叠聚类并成一通：把全部媒体腿与全部信令对话框
  // 全局重绑（SDP 宣告端点 / 无 SDP 时信令对端 IP），按半呼叫形状拆回各自
  // 的通话
  rawCalls = refineCalls(rawCalls, serverIp);
  // 拆分出的新通话也要拿到自己的信令流程/Call-ID，重跑一次关联
  buildSipFlows(rawCalls, captures, serverIp);

  const results: CallInfo[] = [];
  const kinds = streamKinds(captures);
  for (let idx = 0; idx < rawCalls.length; idx++) {
    const call = rawCalls[idx];
    const completeness = assessCallCompleteness(call, fileInfo, serverIp);

    const streamPts = new Map<number, number>();
    for (const leg of call.legs) {
      for (const [ssrc, st] of leg.streams) {
        if (!streamPts.has(ssrc)) streamPts.set(ssrc, st.pt);
      }
    }
    const streamKindOf = new Map<number, 'audio' | 'video' | null>();
    for (const [ssrc, pt] of streamPts) streamKindOf.set(ssrc, ptKind(kinds, ssrc, pt));
    const mediaTypes: string[] = [];
    if ([...streamKindOf.values()].some((k) => k === 'audio')) mediaTypes.push('audio');
    if ([...streamKindOf.values()].some((k) => k === 'video')) mediaTypes.push('video');

    // 实际使用的编码：由 RTP 流真实出现的 PT 反查（静态 PT 名优先，动态
    // PT 96~127 靠 SDP rtpmap 解析；SDP 列出的是候选，不代表在用）。
    // 动态 PT 音频（如 OPUS@96）按解析出的种类归侧，不能只看 PT 号。
    const sdpMap = call.sdpCodecs?.map ?? { audio: {}, video: {} };
    const ptCodec = (kind: 'audio' | 'video', pt: number): string | null =>
      PT_NAMES[pt] ?? sdpMap[kind]?.[String(pt)] ?? null;
    const codecs: { audio: string[]; video: string[] } = {
      audio: [
        ...new Set(
          [...streamPts]
            .filter(([ssrc]) => streamKindOf.get(ssrc) === 'audio')
            .map(([, pt]) => ptCodec('audio', pt))
            .filter((n): n is string => !!n),
        ),
      ].sort(),
      video: [
        ...new Set(
          [...streamPts]
            .filter(([ssrc]) => streamKindOf.get(ssrc) === 'video')
            .map(([, pt]) => ptCodec('video', pt))
            .filter((n): n is string => !!n),
        ),
      ].sort(),
    };
    if (!codecs.video.length) {
      codecs.video = [
        ...new Set(
          [...streamPts]
            .filter(([ssrc]) => streamKindOf.get(ssrc) === 'video')
            .map(([, pt]) => `PT ${pt}（SDP 未抓到）`),
        ),
      ].sort();
    }

    // 接通后媒体区间（通话区间 ≠ 通话媒体区间）：FS 从主叫一呼叫就可能开始
    // 收录 RTP（含回铃音等早期媒体），这里只统计被叫应答之后、首条 BYE 之前
    // 本通话 SSRC 的 RTP 包——即双方真正交换媒体的那段。
    const ans = call.answerTime;
    const bye = call.byeTime;
    let talk: [number, number] = [call.start, call.end];
    if (ans !== null || bye !== null) {
      const lo = ans !== null ? ans : call.start;
      const hi = bye !== null ? bye : call.end;
      let tMin = Infinity;
      let tMax = -Infinity;
      for (const rd of Object.values(captures)) {
        for (const [ssrc, bySeq] of rd.packets) {
          if (!call.ssrcs.has(ssrc)) continue;
          for (const v of bySeq.values()) {
            if (lo <= v.time && v.time <= hi) {
              if (v.time < tMin) tMin = v.time;
              if (v.time > tMax) tMax = v.time;
            }
          }
        }
      }
      if (tMin !== Infinity) talk = [tMin, tMax];
    }
    const talkDur = talk[1] - talk[0];

    const p2p = isDirectMedia(call, serverIp);
    results.push({
      callId: `call_${idx + 1}`,
      ssrcs: [...call.ssrcs].sort((a, b) => a - b),
      startTime: call.start,
      endTime: call.end,
      streams: call.ssrcs.size,
      startStr: fmtTime(call.start),
      endStr: fmtTime(call.end),
      durationS: round1(call.duration),
      answerTime: call.answerTime,
      byeTime: call.byeTime,
      talkStartStr: fmtTime(talk[0]),
      talkEndStr: fmtTime(talk[1]),
      talkDurationS: round1(talkDur),
      files: [...call.files].sort(),
      mediaTypes,
      codecs,
      negotiatedCodecs: call.negotiatedCodecs ?? { audio: [], video: [] },
      negotiatedPerLeg: call.negotiatedPerLeg ?? {},
      fsMedia: fsMediaVerdict(call, p2p, serverIp),
      // FS 媒体转发判定：这通话的音视频流到底有没有经过 FS 转发
      // （点对点直连时为 null，已有专门提示）
      fsRelay: p2p ? null : serverIp ? fsRelayVerdict(call, captures, serverIp) : null,
      sdpAnswered: call.sdpAnswered ?? true,
      isP2p: p2p,
      // 点对点直连时给出两端 IP，供提示文案直接展示（一眼确认）
      p2pEndpoints: p2p
        ? [...new Set(call.legs.flatMap((leg) => [...leg.ips]))].sort()
        : [],
      integrity: completeness,
      signaling: call.sipFlow,
      sipCallIds: [...call.sipCallIds].sort(),
    });
  }
  return results;
}

// ---------------------------------------------------------------------------
// check_capture_consistency：跨抓包一致性检查（传错文件检测）
// ---------------------------------------------------------------------------

/** 检查多份抓包之间是否至少共享一通通话（传错文件检测）。
 * 同一次通话的媒体流 SSRC 在每个经过的抓包点都相同，会被合并进同一通；
 * 因此正常情况下坐席端 / FS 端 / 终端三份抓包至少共同覆盖一通通话。若某
 * 两个角色之间找不到任何共同通话，说明这几个文件很可能不是同一次通话。
 * 例外：点对点直连通话（媒体不经服务器转发，如终端直拨坐席）只会出现在
 * 两个端点各自的抓包里，服务器抓包里天然没有。当所有"无共同通话"的角色
 * 对都含服务器侧抓包、且其余角色之间存在共享的点对点通话时，说明不是传
 * 错文件，提示改为点对点直连（kind='p2p'）：可直接选择该通话分析，服务
 * 器抓包的数据不会参与。
 * 返回 null 表示一致。 */
export function checkCaptureConsistency(
  calls: CallInfo[],
  roles: string[],
  opts: { serverIp: string | null; serverRoles: string[] },
): CaptureConsistencyResult | null {
  const { serverIp, serverRoles } = opts;
  const rs = [...new Set(roles.filter((r) => r))];
  if (rs.length < 2 || !calls.length) return null;

  const roleCalls: Record<string, CallInfo[]> = {};
  for (const r of rs) roleCalls[r] = calls.filter((c) => c.files.includes(r));
  const pairs: { a: string; b: string }[] = [];
  for (let i = 0; i < rs.length; i++) {
    for (let j = i + 1; j < rs.length; j++) {
      if (!calls.some((c) => c.files.includes(rs[i]) && c.files.includes(rs[j]))) {
        pairs.push({ a: rs[i], b: rs[j] });
      }
    }
  }
  if (!pairs.length) return null;

  let serverSide = new Set((serverRoles ?? []).filter((r) => rs.includes(r)));
  if (!serverSide.size && rs.includes('fs')) serverSide = new Set(['fs']);

  let kind: 'p2p' | 'mismatch' = 'mismatch';
  let message: string | null = null;
  // 点对点解释成立的条件：每个失败角色对都含服务器侧抓包（服务器抓不到
  // 这通电话），且非服务器角色之间确实共享着一通媒体直连的通话（两端都
  // 抓到，说明是同一通，而不是各抓各的）
  const directCalls = serverSide.size
    ? calls.filter((c) => c.isP2p && c.files.length >= 2)
    : [];
  if (directCalls.length && pairs.every((p) => serverSide.has(p.a) || serverSide.has(p.b))) {
    kind = 'p2p';
    message = p2pMessage(directCalls, pairs, roleCalls, serverSide, serverIp);
  }

  const roleItems: ConsistencyRoleItem[] = [];
  for (const r of rs) {
    const cs = [...roleCalls[r]].sort((a, b) => a.startTime - b.startTime);
    const overall = cs.length
      ? { start: cs[0].startStr, end: cs[cs.length - 1].endStr, count: cs.length }
      : { count: 0 };
    roleItems.push({
      role: r,
      display: ROLE_DISPLAY[r] ?? r,
      overall,
      calls: cs.map((c) => ({
        label: `通话 ${c.callId.split('_').pop() ?? c.callId}`,
        start: c.startStr,
        end: c.endStr,
      })),
    });
  }

  if (message === null) {
    const totalPairs = (rs.length * (rs.length - 1)) / 2;
    const scope =
      pairs.length === totalPairs
        ? '任意两端抓包之间都没有同一通通话'
        : '部分抓包两两之间没有同一通通话';
    message =
      `这几份抓包里可能不是同一次通话：${scope}。` +
      '请确认上传的文件是否传错；如需继续，请选择其中一通通话单独分析。';
  }
  return { kind, message, roles: roleItems, pairs };
}

/** 点对点直连提示文案：给出直连两端 IP 与服务器 IP，方便一眼确认。 */
function p2pMessage(
  directCalls: CallInfo[],
  pairs: { a: string; b: string }[],
  roleCalls: Record<string, CallInfo[]>,
  serverSide: Set<string>,
  serverIp: string | null,
): string {
  const call = directCalls[0];
  const sharers = call.files
    .filter((r) => !serverSide.has(r))
    .map((r) => ROLE_DISPLAY[r] ?? r)
    .join('、');
  const endpoints = (call.p2pEndpoints ?? []).join(' ↔ ');
  const servers = [
    ...new Set(
      [...serverSide]
        .filter((r) => pairs.some((p) => p.a === r || p.b === r))
        .map((r) => ROLE_DISPLAY[r] ?? r),
    ),
  ]
    .sort()
    .join('、');
  const n = Math.max(...[...serverSide].map((r) => (roleCalls[r] ?? []).length));
  const count =
    directCalls.length > 1 ? `${directCalls.length} 通点对点直连通话` : '点对点直连通话';
  return (
    `检测到${count}：${sharers}之间的通话媒体为端到端直连（${endpoints}），` +
    `未经过 ${servers}（${serverIp}），因此 ${servers}的抓包里没有这通通话` +
    `（其抓到的 ${n} 通为该服务器同时段的其他通话）。` +
    `文件没有传错，选择这通通话分析即可，分析不会使用 ${servers}的数据。`
  );
}
