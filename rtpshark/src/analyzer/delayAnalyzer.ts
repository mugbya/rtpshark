// 延迟分析器（delay_analyzer.py 的 TS 移植）
// 计算 FS 内部处理延迟、跨抓包网络延迟、端到端延迟。
// 支持时钟偏移自动检测和修正。
import type { PacketMap } from './types';

export interface DelayPoint {
  time: number;
  delayMs: number;
}

export interface DelaySummary {
  /** 延迟时间序列 */
  delays: DelayPoint[];
  mean: number;
  median: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  min: number;
  std: number;
  count: number;
  outliers50Ms: number;
  outliers100Ms: number;
}

export interface CrossCaptureDelayResult extends DelaySummary {
  label: string;
  /** 估算的时钟偏移（有共同包时才存在，未取整，等价 np.median） */
  clockOffsetMs?: number;
  detrendedMean?: number;
  detrendedStd?: number;
  detrendedP95?: number;
  detrendedP99?: number;
}

export interface CrossDelayEntry {
  ssrc: number;
  label: string;
  clockOffsetMs?: number;
}

export interface ClockOffsetsResult {
  offsets: Record<string, number>;
  maxOffset: number;
  /** 如果偏移过大则给出警告 */
  warning: string | null;
}

export interface EndToEndDelayResult {
  totalMean: number;
  totalP95: number;
  totalP99: number;
  breakdown: string;
}

// ---------- 数值辅助（等价 numpy 的缺省口径） ----------

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

function meanOf(vals: number[]): number {
  let s = 0;
  for (const v of vals) s += v;
  return s / vals.length;
}

/** 中位数：偶数个取中间两数均值（等价 statistics.median / np.median） */
function medianOf(vals: number[]): number {
  const s = [...vals].sort((a, b) => a - b);
  const n = s.length;
  if (n % 2 === 1) return s[(n - 1) / 2];
  return (s[n / 2 - 1] + s[n / 2]) / 2;
}

/** 总体标准差（numpy 默认 ddof=0） */
function stdOf(vals: number[]): number {
  const m = meanOf(vals);
  let acc = 0;
  for (const v of vals) acc += (v - m) * (v - m);
  return Math.sqrt(acc / vals.length);
}

/** 线性插值百分位（numpy.percentile 缺省 method='linear'） */
function percentileOf(vals: number[], q: number): number {
  const s = [...vals].sort((a, b) => a - b);
  const n = s.length;
  if (n === 1) return s[0];
  const idx = ((n - 1) * q) / 100;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return s[lo];
  return s[lo] + (s[hi] - s[lo]) * (idx - lo);
}

function emptyDelayResult(): DelaySummary {
  return {
    delays: [],
    mean: 0, median: 0, p50: 0, p95: 0, p99: 0,
    max: 0, min: 0, std: 0, count: 0,
    outliers50Ms: 0, outliers100Ms: 0,
  };
}

/** 汇总延迟统计。 */
function summarizeDelays(delays: [number, number][]): DelaySummary {
  if (!delays.length) return emptyDelayResult();

  const vals = delays.map((d) => d[1]);
  return {
    delays: delays.map(([t, d]) => ({ time: t, delayMs: d })),
    mean: roundPy(meanOf(vals), 2),
    median: roundPy(medianOf(vals), 2),
    p50: roundPy(medianOf(vals), 2),
    p95: roundPy(percentileOf(vals, 95), 2),
    p99: roundPy(percentileOf(vals, 99), 2),
    max: roundPy(Math.max(...vals), 2),
    min: roundPy(Math.min(...vals), 2),
    std: roundPy(stdOf(vals), 2),
    count: delays.length,
    outliers50Ms: vals.filter((v) => v > 50).length,
    outliers100Ms: vals.filter((v) => v > 100).length,
  };
}

/**
 * 计算 FS 内部处理延迟（入站 SSRC → 出站 SSRC）。
 *
 * 使用滑动窗口匹配：对每个入站包，找到时间最接近且 >= 入站时间的出站包。
 *
 * @param packetsFs FS 侧 RTP 包字典
 * @param ssrcIn    入站 SSRC（如坐席→FS）
 * @param ssrcOut   出站 SSRC（如 FS→终端）
 */
export function calcFsInternalDelay(
  packetsFs: PacketMap,
  ssrcIn: number,
  ssrcOut: number,
): DelaySummary {
  // [(time, seq)]，按 (time, seq) 排序（等价 Python 对元组列表 sorted）
  const collect = (ssrc: number): [number, number][] => {
    const list: [number, number][] = [];
    const bySeq = packetsFs.get(ssrc);
    if (bySeq) for (const [seq, v] of bySeq) list.push([v.time, seq]);
    list.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    return list;
  };
  const inPkts = collect(ssrcIn);
  const outPkts = collect(ssrcOut);

  if (!inPkts.length || !outPkts.length) return emptyDelayResult();

  const delays: [number, number][] = [];
  let j = 0;
  for (const [inTime] of inPkts) {
    while (j < outPkts.length && outPkts[j][0] < inTime) j += 1;
    if (j < outPkts.length) {
      const delay = (outPkts[j][0] - inTime) * 1000;
      if (delay >= 0 && delay < 500) delays.push([inTime, delay]);
    }
  }

  return summarizeDelays(delays);
}

/**
 * 计算跨抓包延迟（同一 SSRC+seq 在两个抓包点的到达时间差）。
 *
 * @param packetsA 抓包点 A 的 RTP 包
 * @param packetsB 抓包点 B 的 RTP 包
 * @param ssrc     要分析的 SSRC
 * @param labelA   标签（用于结果描述）
 * @param labelB   标签（用于结果描述）
 */
export function calcCrossCaptureDelay(
  packetsA: PacketMap,
  packetsB: PacketMap,
  ssrc: number,
  labelA = 'A',
  labelB = 'B',
): CrossCaptureDelayResult {
  const delays: [number, number][] = [];
  const bySeqB = packetsB.get(ssrc);
  for (const [seq, recA] of packetsA.get(ssrc) ?? []) {
    const recB = bySeqB?.get(seq);
    if (!recB) continue;
    const delay = (recB.time - recA.time) * 1000;
    delays.push([recA.time, delay]);
  }

  const result: CrossCaptureDelayResult = { ...summarizeDelays(delays), label: '' };
  result.label = `${labelA} → ${labelB}`;

  // 时钟偏移估算是中位数
  if (delays.length) {
    result.clockOffsetMs = medianOf(delays.map((d) => d[1]));
    // 去偏移后的延迟
    const offset = result.clockOffsetMs;
    const detrended = delays.map((d) => d[1] - offset);
    result.detrendedMean = meanOf(detrended);
    result.detrendedStd = stdOf(detrended);
    result.detrendedP95 = percentileOf(detrended, 95);
    result.detrendedP99 = percentileOf(detrended, 99);
  }

  return result;
}

/**
 * 检测多个跨抓包延迟中的时钟偏移。
 *
 * @param crossDelays 各跨抓包延迟结果（含估算的时钟偏移）
 */
export function detectClockOffsets(crossDelays: CrossDelayEntry[]): ClockOffsetsResult {
  const offsets: Record<string, number> = {};
  for (const cd of crossDelays) {
    if (cd.clockOffsetMs !== undefined) {
      offsets[cd.label] = cd.clockOffsetMs;
    }
  }

  let warning: string | null = null;
  const values = Object.values(offsets);
  if (values.length) {
    const maxOff = Math.max(...values.map((v) => Math.abs(v)));
    if (maxOff > 500) {
      warning = (`Large clock offset detected (${fmtFixed(maxOff, 0)}ms). ` +
        `Sync NTP on capture machines for more accurate delay measurement.`);
    }
    return {
      offsets,
      maxOffset: maxOff,
      warning,
    };
  }
  return { offsets, maxOffset: 0, warning };
}

/**
 * 估算端到端延迟。
 *
 * @param fsInternalResult FS 内部延迟分析结果
 * @param networkDelayAMs  A→FS 网络延迟估算（默认 2ms LAN）
 * @param networkDelayBMs  FS→B 网络延迟估算（默认 2ms LAN）
 */
export function estimateEndToEndDelay(
  fsInternalResult: DelaySummary | null | undefined,
  networkDelayAMs = 2,
  networkDelayBMs = 2,
): EndToEndDelayResult {
  if (!fsInternalResult || fsInternalResult.count === 0) {
    return { totalMean: 0, totalP95: 0, totalP99: 0, breakdown: '数据不足' };
  }

  const totalMean = fsInternalResult.mean + networkDelayAMs + networkDelayBMs;
  const totalP95 = fsInternalResult.p95 + networkDelayAMs + networkDelayBMs;
  const totalP99 = fsInternalResult.p99 + networkDelayAMs + networkDelayBMs;

  const breakdown = (`网络A→FS: ~${networkDelayAMs}ms + ` +
    `FS内部: ${fmtFixed(fsInternalResult.mean, 1)}ms + ` +
    `网络FS→B: ~${networkDelayBMs}ms = ` +
    `${fmtFixed(totalMean, 1)}ms`);

  return {
    totalMean: roundPy(totalMean, 1),
    totalP95: roundPy(totalP95, 1),
    totalP99: roundPy(totalP99, 1),
    breakdown,
  };
}
