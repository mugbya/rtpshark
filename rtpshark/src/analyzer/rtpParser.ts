// RTP/pcap 解析主模块（rtp_parser.py 的 TS 移植）
// 输入为抓包文件字节（pcap/pcapng），输出 Capture 结构：
// packets（按 (ssrc, seq) 去重）、streams、sipEvents、rtcpEvents、integrity。
import type {
  Capture,
  PacketMap,
  PortPair,
  RtcpEvent,
  RtpPacketRec,
  SdpCodecIdent,
  SdpInfo,
  SipAddr,
  SipEvent,
  StreamInfo,
  StreamPacket,
} from './types';
import { readPcapBytes, buildIntegrity, TRUNC_MIN_BYTES } from './captureIntegrity';
import { parseRtcp } from './rtcpParser';
import { resolveStreamKind } from './streamClassifier';

// SIP 对话相关方法：REGISTER/OPTIONS/SUBSCRIBE 保活不进通话流程
export const SIP_METHODS_OF_INTEREST = new Set([
  'INVITE', 'BYE', 'CANCEL', 'ACK', 'UPDATE', 'PRACK', 'INFO',
]);

// 每条流用于估计 RTP 时钟率的 (到达时刻, 时间戳) 采样上限（尾部窗口）
const CLOCK_SAMPLE_MAX = 64;

const STATIC_PT_NAMES: Record<string, string> = {
  '0': 'PCMU', '3': 'GSM', '4': 'G723', '5': 'DVI4', '6': 'DVI4',
  '7': 'LPC', '8': 'PCMA', '9': 'G722', '10': 'L16', '11': 'L16',
  '12': 'QCELP', '13': 'CN', '14': 'MPA', '15': 'G728', '16': 'DVI4',
  '17': 'DVI4', '18': 'G729', '25': 'CELB', '26': 'JPEG', '28': 'NV',
  '31': 'H261', '32': 'MPV', '33': 'MP2T', '34': 'H263',
};

const STATIC_PT_CLOCK: Record<string, number> = {
  '0': 8000, '3': 8000, '4': 8000, '5': 8000, '6': 16000, '7': 8000,
  '8': 8000, '9': 8000, '10': 44100, '11': 22050, '12': 8000, '13': 8000,
  '14': 90000, '15': 8000, '16': 11025, '17': 22050, '18': 8000,
};

/** 带符号 32 位差值：正常推进为小正数，跨 2^32 回绕不受影响 */
export function signed32(x: number): number {
  x &= 0xffffffff;
  return x >= 0x80000000 ? x - 0x100000000 : x;
}

function parseSipAddr(value: string): SipAddr {
  const out: SipAddr = { name: '', user: '', host: '' };
  if (!value) return out;
  let m = value.match(/"([^"]*)"/);
  if (m) out.name = m[1].trim();
  m = value.match(/<([^>]*)>/);
  const uri = m ? m[1] : value.trim();
  m = uri.match(/^sips?:([^@]*)@([^;>?]+)/);
  if (m) {
    out.user = m[1].trim();
    out.host = m[2].split(':')[0].trim();
  } else if (uri.toLowerCase().startsWith('tel:')) {
    out.user = uri.slice(4).split(';')[0].trim();
  }
  return out;
}

export interface SdpParseResult extends SdpInfo {}

/** 从 SDP 正文提取音视频编码信息与媒体端点 */
export function parseSdpCodecs(body: string): SdpInfo {
  const out: SdpInfo = {
    audio: [], video: [],
    map: { audio: {}, video: {} },
    full: { audio: [], video: [] },
    mapFull: { audio: {}, video: {} },
    endpoints: [],
  };
  let media: string | null = null;
  const order: Record<string, string[]> = { audio: [], video: [] };
  const named: Record<string, Record<string, string>> = { audio: {}, video: {} };
  const rates: Record<string, Record<string, number>> = { audio: {}, video: {} };
  const endpoints = parseSdpEndpoints(body);
  for (const line of body.replace(/\r\n/g, '\n').split('\n')) {
    if (line.startsWith('m=')) {
      const parts = line.split(/\s+/);
      media = parts.length > 1 ? parts[0].slice(2) : null;
      if (media === 'audio' || media === 'video') {
        order[media].push(...parts.slice(3));
      }
    } else if (line.startsWith('a=rtpmap:') && (media === 'audio' || media === 'video')) {
      const bits = line.split(':', 2)[1].trim().split(/\s+/);
      if (bits.length >= 2) {
        named[media][bits[0]] = bits[1].split('/')[0].toUpperCase();
        const clock = bits[1].split('/');
        if (clock.length > 1 && /^\d+$/.test(clock[1])) {
          rates[media][bits[0]] = parseInt(clock[1], 10);
        }
      }
    }
  }
  for (const kind of ['audio', 'video'] as const) {
    for (const pt of order[kind]) {
      const name = named[kind][pt] || STATIC_PT_NAMES[pt];
      if (!name || name.startsWith('TELEPHONE')) continue;
      if (!out[kind].includes(name)) out[kind].push(name);
      if (!(pt in out.map[kind])) out.map[kind][pt] = name;
      let rate = rates[kind][pt] ?? null;
      if (rate === null && pt in STATIC_PT_NAMES) {
        rate = STATIC_PT_CLOCK[pt] ?? (kind === 'video' ? 90000 : 8000);
      }
      const ident: SdpCodecIdent = { name, rate };
      if (!(pt in out.mapFull[kind])) out.mapFull[kind][pt] = ident;
      if (!out.full[kind].some((e) => e.name === ident.name && e.rate === ident.rate)) {
        out.full[kind].push(ident);
      }
    }
  }
  out.endpoints = endpoints;
  return out;
}

/** 提取 SDP 宣告的媒体端点 (kind, addr, port) */
export function parseSdpEndpoints(body: string): { kind: string; addr: string; port: number }[] {
  const endpoints: { kind: string; addr: string; port: number }[] = [];
  let conn: string | null = null;
  let kind: string | null = null;
  let port: number | null = null;
  for (const line of body.replace(/\r\n/g, '\n').split('\n')) {
    if (line.startsWith('c=')) {
      const parts = line.split(/\s+/);
      if (parts.length >= 3) {
        const addr = parts[2].split('/')[0];
        conn = addr && addr !== '0.0.0.0' ? addr : null;
      }
    } else if (line.startsWith('m=')) {
      if (kind && conn && port) endpoints.push({ kind, addr: conn, port });
      const parts = line.split(/\s+/);
      kind = parts.length > 1 ? parts[0].slice(2) : null;
      port = parts.length > 1 && /^\d+$/.test(parts[1]) ? parseInt(parts[1], 10) : null;
      if (kind !== 'audio' && kind !== 'video') {
        kind = null;
        port = null;
      }
    }
  }
  if (kind && conn && port) endpoints.push({ kind, addr: conn, port });
  return endpoints;
}

export interface SipParsedEvent {
  method: string;
  reason: string;
  callId: string;
  cseq: number | null;
  cseqMethod: string;
  from: SipAddr;
  to: SipAddr;
  sdp: SdpInfo;
}

/** 尽力解析 SIP 消息（仅对话方法 + 全部响应码），非信令返回 null */
export function parseSipEvent(payload: Uint8Array): SipParsedEvent | null {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: false }).decode(
      payload.subarray(0, 8000),
    );
  } catch {
    return null;
  }
  const nul = text.indexOf('\0');
  if (nul >= 0) text = text.slice(0, nul);
  const firstLine = text.split('\r\n', 1)[0];
  const parts = firstLine.split(/\s+/);
  let method = '';
  let reason = '';
  if (parts.length === 3 && parts[2].startsWith('SIP/')) {
    method = parts[0];
    if (!SIP_METHODS_OF_INTEREST.has(method)) return null;
  } else if (parts.length >= 2 && parts[0].startsWith('SIP/')) {
    method = parts[1];
    reason = parts.slice(2).join(' ');
    if (!(/^\d+$/.test(method) && +method >= 100 && +method <= 699)) return null;
  } else {
    return null;
  }
  let callId = '';
  let cseqMethod = '';
  let cseqNum: number | null = null;
  let fromHdr: SipAddr = { name: '', user: '', host: '' };
  let toHdr: SipAddr = { name: '', user: '', host: '' };
  for (const line of text.split('\r\n')) {
    if (!callId && (line.startsWith('Call-ID:') || line.startsWith('i:'))) {
      callId = line.slice(line.indexOf(':') + 1).trim();
    } else if (!cseqMethod && line.startsWith('CSeq:')) {
      const cseqParts = line.slice(line.indexOf(':') + 1).trim().split(/\s+/);
      if (cseqParts.length) {
        cseqMethod = cseqParts[cseqParts.length - 1];
        if (/^\d+$/.test(cseqParts[0])) cseqNum = parseInt(cseqParts[0], 10);
      }
    } else if (fromHdr.name === '' && fromHdr.user === '' && fromHdr.host === '' &&
               (line.startsWith('From:') || line.startsWith('f:'))) {
      fromHdr = parseSipAddr(line.slice(line.indexOf(':') + 1));
    } else if (toHdr.name === '' && toHdr.user === '' && toHdr.host === '' &&
               (line.startsWith('To:') || line.startsWith('t:'))) {
      toHdr = parseSipAddr(line.slice(line.indexOf(':') + 1));
    }
  }
  if (!/^\d+$/.test(method)) {
    if (!SIP_METHODS_OF_INTEREST.has(method)) return null;
  } else if (cseqMethod && !SIP_METHODS_OF_INTEREST.has(cseqMethod)) {
    return null;
  }
  const bodyIdx = text.indexOf('\r\n\r\n');
  const body = bodyIdx >= 0 ? text.slice(bodyIdx + 4) : '';
  const sdp = body ? parseSdpCodecs(body) : {
    audio: [], video: [],
    map: { audio: {}, video: {} },
    full: { audio: [], video: [] },
    mapFull: { audio: {}, video: {} },
    endpoints: [],
  };
  return {
    method, reason, callId,
    cseq: cseqNum, cseqMethod,
    from: fromHdr, to: toHdr, sdp,
  };
}

export interface RtpHeaderResult {
  pt: number;
  seq: number;
  ts: number;
  ssrc: number;
  payload: Uint8Array;
}

/** 解析 RTP 头；非 RTP 返回 null */
export function parseRtpHeader(data: Uint8Array): RtpHeaderResult | null {
  if (data.length < 12) return null;
  const version = (data[0] >> 6) & 0x03;
  if (version !== 2) return null;
  // 排除 RTCP（同为 version 2，字节 1 的完整值落在 200-206）
  if (data[1] >= 200 && data[1] <= 206) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const pt = data[1] & 0x7f;
  const seq = dv.getUint16(2);
  const ts = dv.getUint32(4);
  const ssrc = dv.getUint32(8);
  return { pt, seq, ts, ssrc, payload: data.subarray(12) };
}

// ---------------- 链路层 / IP / UDP ----------------

interface UdpInfo {
  srcIp: string;
  dstIp: string;
  sport: number;
  dport: number;
  payload: Uint8Array;
}

function parseLinkLayer(frame: Uint8Array): Uint8Array | null {
  // Ethernet (含 802.1Q VLAN)、Linux SLL、Raw IP
  if (frame.length < 14) return null;
  const et = (frame[12] << 8) | frame[13];
  if (et === 0x0800) return frame.subarray(14);
  if (et === 0x8100 || et === 0x88a8) {
    // VLAN 标签后的真实 EtherType 在 offset 16
    if (frame.length < 18) return null;
    const et2 = (frame[16] << 8) | frame[17];
    if (et2 === 0x0800) return frame.subarray(18);
    return null;
  }
  // Linux cooked (SLL)：协议字段在 offset 14
  if (frame[0] === 0 && frame[1] <= 4 && ((frame[14] << 8) | frame[15]) === 0x0800) {
    return frame.subarray(16);
  }
  // Raw IP：首半字节 4 = IPv4
  if ((frame[0] >> 4) === 4) return frame;
  return null;
}

interface Ipv4Info {
  srcIp: string;
  dstIp: string;
  protocol: number;
  id: number;
  fragOffset: number; // 8 字节单位
  mf: boolean;
  l4: Uint8Array; // 本分片携带的 L4 数据（不含 IP 头）
  totalLength: number; // IP 总长（线上应传长度）
}

function parseIpv4(data: Uint8Array): Ipv4Info | null {
  if (data.length < 20) return null;
  if (data[0] >> 4 !== 4) return null;
  const ihl = (data[0] & 0x0f) * 4;
  if (ihl < 20 || data.length < ihl) return null;
  const totalLength = (data[2] << 8) | data[3];
  const id = (data[4] << 8) | data[5];
  const flagsFrag = (data[6] << 8) | data[7];
  const mf = (flagsFrag & 0x2000) !== 0;
  const fragOffset = (flagsFrag & 0x1fff) * 8;
  const protocol = data[9];
  const src = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
  const dst = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;
  return {
    srcIp: src, dstIp: dst, protocol, id,
    fragOffset, mf,
    l4: data.subarray(ihl),
    totalLength,
  };
}

/** IPv4 分片重组缓存：key -> {offsets, have, total} */
interface FragEntry { parts: Map<number, Uint8Array>; have: number; total: number | null }

const fragCache = new Map<string, FragEntry>();

function fragKeyOf(ip: Ipv4Info): string {
  return `${ip.srcIp}>${ip.dstIp}#${ip.id}p${ip.protocol}`;
}

/** 尝试把一个 IPv4 包（可能是分片）还原成完整 L4 数据报。
 * 非分片直接返回 l4；分片进缓存，集齐后重组返回；未齐返回 null。 */
function ipDefragment(ip: Ipv4Info): { l4: Uint8Array } | null {
  const isFragment = ip.mf || ip.fragOffset > 0;
  if (!isFragment) {
    // 用 IP 总长剥掉链路层填充（最小以太网帧的 pad 字节）
    const l4Len = ip.totalLength >= 20 ? ip.totalLength - 20 : ip.l4.length;
    return { l4: ip.l4.subarray(0, Math.min(l4Len, ip.l4.length)) };
  }
  const key = fragKeyOf(ip);
  let entry = fragCache.get(key);
  if (!entry) {
    entry = { parts: new Map(), have: 0, total: null };
    fragCache.set(key, entry);
  }
  const seg = ip.l4;
  if (!entry.parts.has(ip.fragOffset)) {
    entry.parts.set(ip.fragOffset, seg);
    entry.have += seg.length;
  }
  if (!ip.mf && entry.total === null) entry.total = ip.fragOffset + seg.length;
  if (entry.total !== null && entry.have >= entry.total) {
    const out = new Uint8Array(entry.total);
    for (const [off, part] of entry.parts) {
      out.set(part.subarray(0, Math.min(part.length, entry.total - off)), off);
    }
    fragCache.delete(key);
    return { l4: out };
  }
  return null;
}

function parseUdp(ip: Ipv4Info, l4: Uint8Array): UdpInfo | null {
  if (l4.length < 8) return null;
  const dv = new DataView(l4.buffer, l4.byteOffset, l4.byteLength);
  const sport = dv.getUint16(0);
  const dport = dv.getUint16(2);
  const len = dv.getUint16(4);
  const payload = l4.subarray(8, len >= 8 ? Math.min(len, l4.length) : l4.length);
  return { srcIp: ip.srcIp, dstIp: ip.dstIp, sport, dport, payload };
}

// ---------------- 主提取流程 ----------------

export function extractRtpPackets(
  fileBytes: Uint8Array,
  includePayload = false,
): Capture {
  const { records, stats } = readPcapBytes(fileBytes);

  const packets: PacketMap = new Map();
  const ips = new Set<string>();
  const ssrcs = new Set<number>();
  const streamAcc = new Map<number, { count: number; pt: Set<number>; ips: Set<string>; portPairs: Set<string> }>();
  let captureStart: number | null = null;
  let captureEnd: number | null = null;
  const sipEvents: SipEvent[] = [];
  const rtcpEvents: RtcpEvent[] = [];
  const tsSamples = new Map<number, [number, number][]>();
  let truncAll = 0;
  let truncRtp = 0;
  let maxMissing = 0;
  let allCount = 0;

  for (const rec of records) {
    allCount += 1;
    const t = rec.time;
    if (captureStart === null || t < captureStart) captureStart = t;
    if (captureEnd === null || t > captureEnd) captureEnd = t;
    const wirelen = rec.wirelen;
    const missing = wirelen ? wirelen - rec.data.length : 0;
    const truncated = missing >= TRUNC_MIN_BYTES;
    if (truncated) {
      truncAll += 1;
      maxMissing = Math.max(maxMissing, missing);
    }
    const l3 = parseLinkLayer(rec.data);
    if (!l3) continue;
    const ip = parseIpv4(l3);
    if (!ip || ip.protocol !== 17) continue;

    const defragged = ipDefragment(ip);
    if (!defragged) continue; // 分片未集齐
    const udp = parseUdp(ip, defragged.l4);
    if (!udp) continue;

    // SIP 信令（完整性信号 + 通话流程展示）
    if (udp.sport === 5060 || udp.dport === 5060) {
      const ev = parseSipEvent(udp.payload);
      if (ev) {
        sipEvents.push({ ...ev, time: t, src: udp.srcIp, dst: udp.dstIp });
      }
      continue;
    }
    const rtp = parseRtpHeader(udp.payload);
    if (rtp) {
      const { pt, seq, ts, ssrc } = rtp;
      if (truncated) truncRtp += 1;
      let bySeq = packets.get(ssrc);
      if (!bySeq) {
        bySeq = new Map();
        packets.set(ssrc, bySeq);
      }
      // 仅保留每个 (ssrc, seq) 的首现（去重）
      if (!bySeq.has(seq)) {
        const recItem: RtpPacketRec = {
          time: t, rtpTs: ts, pt,
          srcIp: udp.srcIp, dstIp: udp.dstIp,
          srcPort: udp.sport, dstPort: udp.dport,
        };
        if (includePayload) recItem.payload = rtp.payload;
        bySeq.set(seq, recItem);
      }
      ips.add(udp.srcIp);
      ips.add(udp.dstIp);
      ssrcs.add(ssrc);
      let st = streamAcc.get(ssrc);
      if (!st) {
        st = { count: 0, pt: new Set(), ips: new Set(), portPairs: new Set() };
        streamAcc.set(ssrc, st);
      }
      st.count += 1;
      st.pt.add(pt);
      st.ips.add(`${udp.srcIp}>${udp.dstIp}`);
      st.portPairs.add(`${udp.srcIp}|${udp.sport}|${udp.dstIp}|${udp.dport}`);
      let sample = tsSamples.get(ssrc);
      if (!sample) {
        sample = [];
        tsSamples.set(ssrc, sample);
      }
      if (sample.length >= CLOCK_SAMPLE_MAX) sample.shift();
      sample.push([t, ts]);
    } else if (udp.payload.length >= 4) {
      // RTCP（SR/RR/NACK/PLI/FIR）
      for (const ev of parseRtcp(udp.payload)) {
        rtcpEvents.push({ ...ev, time: t, src: udp.srcIp, dst: udp.dstIp });
      }
    }
  }

  // —— 流种类/编码解析（SDP 端点绑定 → rtpmap → 实测时钟 → 静态表）——
  const portKinds: Record<string, 'audio' | 'video'> = {};
  const ptMaps = { audio: {}, video: {} } as {
    audio: Record<string, { name: string; rate: number | null }>;
    video: Record<string, { name: string; rate: number | null }>;
  };
  for (const ev of sipEvents) {
    const sdp = ev.sdp;
    for (const ep of sdp?.endpoints || []) {
      if ((ep.kind === 'audio' || ep.kind === 'video') && ep.addr && ep.port) {
        if (!(`${ep.addr}:${ep.port}` in portKinds)) {
          portKinds[`${ep.addr}:${ep.port}`] = ep.kind as 'audio' | 'video';
        }
      }
    }
    for (const kind of ['audio', 'video'] as const) {
      for (const [pt, ident] of Object.entries(sdp?.mapFull?.[kind] || {})) {
        if (!(pt in ptMaps[kind])) ptMaps[kind][pt] = ident;
      }
    }
  }

  const estClockOf = (ssrc: number): number | null => {
    const sample = tsSamples.get(ssrc) || [];
    const rates: number[] = [];
    for (let i = 1; i < sample.length; i++) {
      const [t0, ts0] = sample[i - 1];
      const [t1, ts1] = sample[i];
      const dt = t1 - t0;
      const dts = signed32(ts1 - ts0);
      if (dt > 0.001 && dts > 0) rates.push(dts / dt);
    }
    if (rates.length < 4) return null;
    rates.sort((a, b) => a - b);
    return rates[Math.floor(rates.length / 2)];
  };

  const streams: Record<number, StreamInfo> = {};
  for (const [ssrc, info] of streamAcc) {
    if (info.count < 10) continue; // 过滤包数太少的流
    const portPairs: PortPair[] = [...info.portPairs].map((s) => {
      const [a, b, c, d] = s.split('|');
      return [a, parseInt(b, 10), c, parseInt(d, 10)];
    });
    const [kind, codec, clock] = resolveStreamKind(
      portPairs,
      [...info.pt],
      estClockOf(ssrc),
      portKinds,
      ptMaps,
    );
    streams[ssrc] = {
      count: info.count,
      pt: [...info.pt].sort((a, b) => a - b),
      ips: [...info.ips].map((s) => s.split('>') as [string, string]),
      portPairs,
      kind,
      codec,
      clock,
    };
  }

  const integrity = buildIntegrity({
    allPackets: allCount,
    truncated: truncAll,
    truncatedRtp: truncRtp,
    maxMissingBytes: maxMissing,
    fileCut: false,
    snaplen: stats?.snaplen ?? null,
    headerTruncated: stats?.truncatedRecords ?? null,
    tailIncomplete: stats?.tailIncomplete ?? false,
    minCapturedTrunc: stats?.minCapturedTrunc ?? null,
  });

  return {
    packets,
    totalCount: [...packets.values()].reduce((n, m) => n + m.size, 0),
    ips: [...ips],
    ssrcs: [...ssrcs],
    streams,
    captureStart,
    captureEnd,
    sipEvents,
    rtcpEvents,
    integrity,
  };
}

/** 取某条流的所有包，按抓包时间排序 */
export function getStreamPackets(
  packets: PacketMap,
  ssrc: number,
): StreamPacket[] {
  const bySeq = packets.get(ssrc);
  if (!bySeq) return [];
  const result: StreamPacket[] = [];
  for (const [seq, v] of bySeq) {
    result.push({
      time: v.time, seq, rtpTs: v.rtpTs, pt: v.pt,
      srcIp: v.srcIp, dstIp: v.dstIp, srcPort: v.srcPort, dstPort: v.dstPort,
      payload: v.payload,
    });
  }
  result.sort((a, b) => a.time - b.time);
  return result;
}
