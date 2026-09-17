// 分段延迟链路定位（delay_chains.py 的 TS 移植）
//
// 把"哪一侧听到的声音延迟大"拆成逐段测量（主叫→坐席 / 坐席→主叫 两个方向）：
//
// - 端点→FS 网络段：同一 (SSRC, seq) 的包在端点抓包与 FS 抓包里的到达时刻差
//   （calc_cross_capture_delay）。两台抓包机时钟不同步时，测量值里混入恒定
//   偏移（clock_offset_ms 为中位数估计），绝对值仅供参考；去偏移后的波动
//   （detrended_p95）才反映该段的抖动/突发。
// - FS 内部处理段：同一抓包内"入站 SSRC → 出站 SSRC"的转发间隔
//   （calc_fs_internal_delay），单一时钟、测量精确，是链路中最可信的一段。
// - FS→端点网络段：同跨抓包匹配。
//
// 时钟偏移的消除：同一段路径往返两个方向的测量之和会抵消偏移（上行含
// C_端−C_FS，反向下行含 C_FS−C_端），roundtrip 一节给出该无偏移参考值，
// 用它判断"这条链路整体是否偏慢"。接收端抖动缓冲与播放设备等应用层延迟
// 在抓包中不可见，不在测量范围。
import type { Capture, CallInfo } from './types';
import type { CallParties } from './callDetector';
import { pickCallStream } from './streamClassifier';
import { calcCrossCaptureDelay, calcFsInternalDelay } from './delayAnalyzer';

// 跨抓包段：去时钟偏移后的 P95 波动超过此值，视为该段抖动/突发偏大
export const CROSS_HIGH_P95_MS = 150.0;
// FS 内部段：均值超过此值视为处理延迟偏高（与结论阈值一致）
export const FS_INTERNAL_HIGH_MS = 50.0;
// 往返参考值（上+下两段均值之和）超过此值提示链路整体偏慢
export const ROUNDTRIP_HIGH_MS = 300.0;

const ROLE_NAMES: Record<string, string> = { terminal: '主叫', seat: '被叫' };

export type ChainSegmentKind = 'cross' | 'fs_internal';
export type ChainSegmentStatus = 'ok' | 'high' | 'unavailable';
export type ChainVerdict = 'ok' | 'high' | 'partial' | 'unavailable';

export interface ChainSegment {
  kind: ChainSegmentKind;
  name: string;
  ssrc: string | null;
  available: boolean;
  count: number;
  mean: number | null;
  p50: number | null;
  p95: number | null;
  clockOffsetMs: number | null;
  detrendedP95: number | null;
  status: ChainSegmentStatus;
  note: string;
}

export interface ChainDirection {
  label: string;
  speaker: string;
  listener: string;
  verdict: ChainVerdict;
  verdictText: string;
  segments: ChainSegment[];
  totalMean: number | null;
  totalNote: string | null;
}

export interface ChainRoundtrip {
  pair: string;
  ms: number;
  status: 'ok' | 'high';
  note: string;
}

export interface DelayChainResult {
  available: boolean;
  p2p: boolean;
  directions: ChainDirection[];
  roundtrip: ChainRoundtrip[];
  notes: string[];
}

/** buildDelayChains 需要的通话字段（CallInfo 已含 isP2p） */
type ChainCall = CallInfo;

interface DirectionSpec {
  speakerRole: string;
  listenerRole: string;
  speakerIp: string | null;
  listenerIp: string | null;
  speakerName: string;
  listenerName: string;
}

/** Python 风格 round（round-half-to-even） */
function roundPy(x: number, digits = 0): number {
  const f = Math.pow(10, digits);
  const y = x * f;
  const fl = Math.floor(y);
  const diff = y - fl;
  let r: number;
  if (diff > 0.5) r = fl + 1;
  else if (diff < 0.5) r = fl;
  else r = fl % 2 === 0 ? fl : fl + 1;
  return r / f;
}

/** 等价 '{:.Nf}'.format 的展示用格式化（先按银行家舍入） */
function fmtFixed(x: number, digits: number): string {
  return roundPy(x, digits).toFixed(digits);
}

function ssrcHex(ssrc: number): string {
  return `0x${(ssrc >>> 0).toString(16).padStart(8, '0')}`;
}

function segBase(kind: ChainSegmentKind, name: string, ssrc: number | null): ChainSegment {
  return {
    kind,
    name,
    ssrc: ssrc !== null ? ssrcHex(ssrc) : null,
    available: false,
    count: 0,
    mean: null,
    p50: null,
    p95: null,
    clockOffsetMs: null,
    detrendedP95: null,
    status: 'unavailable',
    note: '',
  };
}

/** 跨抓包网络段：同一 (SSRC, seq) 在两个抓包点的到达时刻差。 */
function crossSegment(
  capA: Capture | null,
  capB: Capture | null,
  ssrc: number | null,
  name: string,
  aName: string,
  bName: string,
): ChainSegment {
  const seg = segBase('cross', name, ssrc);
  if (ssrc === null) {
    seg.note = '未识别该段媒体流';
    return seg;
  }
  const missing = ([([capA, aName] as const), ([capB, bName] as const)] as const)
    .filter(([c]) => c === null)
    .map(([, n]) => n);
  if (missing.length) {
    seg.note = `缺少${missing.join('、')}，无法比对到达时刻`;
    return seg;
  }
  const r = calcCrossCaptureDelay(capA!.packets, capB!.packets, ssrc, aName, bName);
  if (r.count === 0) {
    seg.note = (`两个抓包点未匹配到共同包` +
      `（${aName}或${bName}可能未覆盖该流）`);
    return seg;
  }
  const offset = r.clockOffsetMs;
  const detP95 = roundPy(r.detrendedP95 ?? 0.0, 2);
  seg.available = true;
  seg.count = r.count;
  seg.mean = r.mean;
  seg.p50 = r.p50;
  seg.p95 = r.p95;
  seg.clockOffsetMs = offset !== undefined ? roundPy(offset, 2) : null;
  seg.detrendedP95 = detP95;
  const notes: string[] = [];
  if (offset !== undefined && Math.abs(offset) > 300) {
    notes.push(`两台抓包机时钟差异约 ${fmtFixed(offset, 0)}ms（含传播时延），` +
      '绝对值不可信');
  }
  if (detP95 > CROSS_HIGH_P95_MS) {
    seg.status = 'high';
    notes.push(`去偏移后 P95 波动 ${fmtFixed(detP95, 0)}ms，该段抖动/突发偏大`);
  } else {
    seg.status = 'ok';
    notes.push(`去偏移后波动 P95 ${fmtFixed(detP95, 0)}ms`);
  }
  seg.note = notes.join('；');
  return seg;
}

/** FS 内部处理段：同一抓包内入站→出站的转发间隔（单时钟，可信）。 */
function fsSegment(
  fsCap: Capture | null,
  ssrcIn: number | null,
  ssrcOut: number | null,
): ChainSegment {
  const seg = segBase('fs_internal', 'FS 内部处理', ssrcIn);
  if (fsCap === null) {
    seg.note = '缺少 FS 抓包，无法测量';
    return seg;
  }
  if (ssrcIn === null || ssrcOut === null) {
    seg.note = '未同时识别该方向的入站/出站流';
    return seg;
  }
  seg.ssrc = `${ssrcHex(ssrcIn)} → ${ssrcHex(ssrcOut)}`;
  const r = calcFsInternalDelay(fsCap.packets, ssrcIn, ssrcOut);
  if (r.count === 0) {
    seg.note = '入站→出站未匹配到转发对（FS 可能未转发该方向媒体）';
    return seg;
  }
  seg.available = true;
  seg.count = r.count;
  seg.mean = r.mean;
  seg.p50 = r.p50;
  seg.p95 = r.p95;
  if (r.mean >= FS_INTERNAL_HIGH_MS) {
    seg.status = 'high';
    seg.note = `FS 内部处理延迟偏高（均值 ${fmtFixed(r.mean, 1)}ms）`;
  } else {
    seg.status = 'ok';
    seg.note = `单时钟测量可信（均值 ${fmtFixed(r.mean, 1)}ms）`;
  }
  return seg;
}

/** 构建一个方向的分段链路。返回 dir 为 null 表示完全无数据。 */
function chainForDirection(
  captures: Record<string, Capture>,
  fsCap: Capture | null,
  callSsrcs: number[],
  serverIp: string | null,
  p2p: boolean,
  spec: DirectionSpec,
): { dir: ChainDirection | null; segs: Map<string, ChainSegment> } {
  const spkCap = captures[spec.speakerRole] ?? null;
  const lstCap = captures[spec.listenerRole] ?? null;
  if (!spkCap && !lstCap && !fsCap) return { dir: null, segs: new Map() };

  const peerOfSpeaker = p2p ? spec.listenerIp : serverIp;
  const peerOfListener = p2p ? spec.speakerIp : serverIp;

  // 选流：上行=发言端发出的流（端点抓包优先，FS 抓包按发言端 IP 兜底）；
  // 下行=听者收到的流（端点抓包优先，FS 抓包按听者 IP 兜底）。
  // p2p 且无 SIP 双方 IP 时退化为"端点抓包内取最大通话流"（方向标注可能
  // 随抓包内容互换，但两段测量仍然成立）
  let uplink: number | null = null;
  if (spkCap) {
    if (peerOfSpeaker) {
      uplink = pickCallStream(spkCap, callSsrcs, null, peerOfSpeaker);
    }
    if (uplink === null && p2p) {
      uplink = pickCallStream(spkCap, callSsrcs);
    }
  }
  if (uplink === null && fsCap && spec.speakerIp) {
    uplink = pickCallStream(fsCap, callSsrcs, spec.speakerIp, null);
  }
  let downlink: number | null = null;
  if (lstCap) {
    if (peerOfListener) {
      downlink = pickCallStream(lstCap, callSsrcs, peerOfListener, null);
    }
    if (downlink === null && p2p) {
      downlink = pickCallStream(lstCap, callSsrcs);
    }
  }
  if (downlink === null && fsCap && spec.listenerIp) {
    downlink = pickCallStream(fsCap, callSsrcs, null, spec.listenerIp);
  }

  if (uplink === null && downlink === null) return { dir: null, segs: new Map() };

  let segments: ChainSegment[];
  const segs = new Map<string, ChainSegment>();
  if (p2p) {
    segments = [crossSegment(
      spkCap, lstCap, uplink !== null ? uplink : downlink,
      `直连（${spec.speakerName} → ${spec.listenerName}）`,
      `${spec.speakerName}端抓包`, `${spec.listenerName}端抓包`,
    )];
  } else {
    const upSeg = crossSegment(
      spkCap, fsCap, uplink, `${spec.speakerName} → FS`,
      `${spec.speakerName}端抓包`, 'FS 抓包',
    );
    const fsSeg = fsSegment(fsCap, uplink, downlink);
    const downSeg = crossSegment(
      fsCap, lstCap, downlink, `FS → ${spec.listenerName}`,
      'FS 抓包', `${spec.listenerName}端抓包`,
    );
    segments = [upSeg, fsSeg, downSeg];
    segs.set(`${spec.speakerRole}|up`, upSeg);
    segs.set(`${spec.listenerRole}|down`, downSeg);
  }

  const avail = segments.filter((s) => s.available);
  const highs = avail.filter((s) => s.status === 'high');
  let verdict: ChainVerdict;
  let text: string;
  if (!avail.length) {
    verdict = 'unavailable';
    text = '缺少可比对的抓包点，无法测量该方向延迟';
  } else if (highs.length) {
    verdict = 'high';
    text = '以下段延迟/波动偏高：' + highs.map((s) => s.name).join('、');
    if (avail.length < segments.length) {
      text += '（另有未测到的段，见明细）';
    }
  } else if (avail.length < segments.length) {
    verdict = 'partial';
    text = ('已测到的段延迟正常；'
      + segments.filter((s) => !s.available).map((s) => s.name).join('、')
      + ' 未测到（缺抓包点）');
  } else {
    verdict = 'ok';
    text = '各段延迟均在正常范围';
  }

  const totalMean = avail.length
    ? roundPy(avail.reduce((acc, s) => acc + (s.mean as number), 0), 1)
    : null;
  let totalNote: string | null = null;
  if (avail.some((s) => s.kind === 'cross' && s.available)) {
    totalNote = '跨抓包段的均值含抓包间时钟偏移，仅供参考';
  }
  const label = `${spec.speakerName} → ${spec.listenerName}`;
  return {
    dir: {
      label,
      speaker: spec.speakerName,
      listener: spec.listenerName,
      verdict,
      verdictText: text,
      segments,
      totalMean,
      totalNote,
    },
    segs,
  };
}

/**
 * 按通话的两个方向构建分段延迟链路。
 *
 * @param captures {role: Capture}，角色键如 terminal / seat / fs
 * @param call     detect_calls 输出的单通通话（ssrcs / isP2p 等）
 * @param serverIp 服务器 IP
 * @param parties  SIP 识别的双方 IP（callerIp / answererIp），可选；
 *                 缺失时无法从 FS 抓包兜底选流
 */
export function buildDelayChains(
  captures: Record<string, Capture>,
  call: CallInfo,
  serverIp: string | null,
  parties?: CallParties | null,
): DelayChainResult {
  const callExt = call as ChainCall;
  const callSsrcs = callExt.ssrcs || [];
  const fsCap = captures['fs'] ?? captures['FS'] ?? null;
  const p2p = !!callExt.isP2p;
  const callerIp = parties?.callerIp ?? null;
  const answererIp = parties?.answererIp ?? null;

  const specs: DirectionSpec[] = [];
  for (const [speakerRole, listenerRole, spkKey, lstKey] of [
    ['terminal', 'seat', 'callerIp', 'answererIp'],
    ['seat', 'terminal', 'answererIp', 'callerIp'],
  ] as const) {
    specs.push({
      speakerRole,
      listenerRole,
      speakerIp: spkKey === 'callerIp' ? callerIp : answererIp,
      listenerIp: lstKey === 'callerIp' ? callerIp : answererIp,
      speakerName: ROLE_NAMES[speakerRole] ?? speakerRole,
      listenerName: ROLE_NAMES[listenerRole] ?? listenerRole,
    });
  }

  const directions: ChainDirection[] = [];
  // (role, 'up'|'down') -> 段结果，供往返合并
  const segmentsByKey = new Map<string, ChainSegment>();
  for (const spec of specs) {
    const { dir, segs } = chainForDirection(
      captures, fsCap, callSsrcs, serverIp, p2p, spec,
    );
    if (dir !== null) {
      directions.push(dir);
      for (const [k, v] of segs) segmentsByKey.set(k, v);
    }
  }

  const roundtrips: ChainRoundtrip[] = [];
  for (const role of ['terminal', 'seat']) {
    const up = segmentsByKey.get(`${role}|up`);
    const down = segmentsByKey.get(`${role}|down`);
    if (!(up && down && up.available && down.available)) continue;
    const name = ROLE_NAMES[role] ?? role;
    const ms = roundPy((up.mean as number) + (down.mean as number), 1);
    roundtrips.push({
      pair: `${name}端往返（${name}→FS→${name}）`,
      ms,
      status: ms > ROUNDTRIP_HIGH_MS ? 'high' : 'ok',
      note: '往返两段的时钟偏移互相抵消，此值不含抓包间时钟差',
    });
  }

  const available = directions.some((d) => d.segments.some((s) => s.available)) ||
    roundtrips.length > 0;

  const notes: string[] = [];
  if (p2p) {
    notes.push('点对点直连：链路只有一段网络路径，无 FS 内部段');
  } else {
    notes.push('跨抓包段的绝对延迟同时包含真实传播时延与抓包机时钟偏移，' +
      '单段测量无法区分二者；往返之和可抵消时钟偏移，' +
      '见往返参考值');
    notes.push('接收端抖动缓冲与播放设备延迟不在抓包中体现，' +
      '测量值为网络传输 + FS 处理延迟');
  }
  return {
    available,
    p2p,
    directions,
    roundtrip: roundtrips,
    notes,
  };
}
