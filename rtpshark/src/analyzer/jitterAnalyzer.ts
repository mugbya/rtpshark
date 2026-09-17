// 抖动分析器（jitter_analyzer.py 的 TS 移植）
// 分析 RTP 流的包间隔（Inter-packet Gap）稳定性。
import type { PacketMap } from './types';
import { getStreamPackets } from './rtpParser';

export interface GapSample {
  time: number;
  gapMs: number;
}

export interface InterPacketGapsResult {
  gaps: GapSample[];
  count: number;
  mean: number;
  median: number;
  std: number;
  p95: number;
  p99: number;
  max: number;
  abnormalCount: number; // 间隔 >100ms 的次数
  expectedInterval: number; // 推算的理想间隔
}

export interface DriftSample {
  time: number;
  offsetMs: number;
}

export interface CumulativeDriftResult {
  drift: DriftSample[];
  totalDriftMs: number; // 最终累积偏移
  driftRate: number; // 漂移速率 (ms/s)
}

export interface JitterCompareItem {
  label: string;
  mean: number;
  median: number;
  std: number;
  abnormalCount: number;
  expectedInterval: number;
}

export interface JitterCompareResult {
  comparison: JitterCompareItem[];
  worstLabel: string | null; // 抖动最严重的流
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

/**
 * 理想间隔 = 出现次数最多的间隔（众数）。
 * 等价 np.histogram(vals, bins=50, range=(0, 50))，范围外的值不参与统计；
 * argmax 并列时取最左侧的桶（与 numpy 一致）。
 */
function histogramMode(vals: number[]): number {
  const bins = 50;
  const lo = 0;
  const hi = 50;
  const width = (hi - lo) / bins;
  const hist = new Array<number>(bins).fill(0);
  for (const v of vals) {
    if (v < lo || v > hi) continue;
    let b = Math.floor((v - lo) / width);
    if (b >= bins) b = bins - 1; // 右端点归入最后一桶
    hist[b] += 1;
  }
  let best = 0;
  for (let i = 1; i < bins; i++) if (hist[i] > hist[best]) best = i;
  return lo + best * width + width / 2;
}

function emptyGapResult(): InterPacketGapsResult {
  return {
    gaps: [],
    count: 0,
    mean: 0, median: 0, std: 0,
    p95: 0, p99: 0, max: 0,
    abnormalCount: 0,
    expectedInterval: 0,
  };
}

/**
 * 计算指定 SSRC 的包间隔。
 *
 * @param packets   RTP 包字典
 * @param ssrc      要分析的 SSRC
 * @param maxGapMs  最大合理间隔（超过此值视为异常/静音）
 */
export function calcInterPacketGaps(
  packets: PacketMap,
  ssrc: number,
  maxGapMs = 200,
): InterPacketGapsResult {
  const pkts = getStreamPackets(packets, ssrc);
  if (pkts.length < 2) return emptyGapResult();

  const gaps: GapSample[] = [];
  for (let i = 1; i < pkts.length; i++) {
    const gap = (pkts[i].time - pkts[i - 1].time) * 1000;
    if (0 < gap && gap < maxGapMs) {
      gaps.push({ time: pkts[i].time, gapMs: gap });
    }
  }

  if (!gaps.length) return emptyGapResult();

  const vals = gaps.map((g) => g.gapMs);
  const expected = histogramMode(vals);

  return {
    gaps,
    count: gaps.length,
    mean: roundPy(meanOf(vals), 2),
    median: roundPy(medianOf(vals), 2),
    std: roundPy(stdOf(vals), 2),
    p95: roundPy(percentileOf(vals, 95), 2),
    p99: roundPy(percentileOf(vals, 99), 2),
    max: roundPy(Math.max(...vals), 2),
    abnormalCount: vals.filter((v) => v > 100).length,
    expectedInterval: roundPy(expected, 1),
  };
}

/**
 * 计算累积时钟漂移（相对理想间隔的偏移）。
 */
export function calcCumulativeDrift(
  packets: PacketMap,
  ssrc: number,
  expectedIntervalMs?: number,
): CumulativeDriftResult {
  const pkts = getStreamPackets(packets, ssrc);
  if (pkts.length < 2) {
    return { drift: [], totalDriftMs: 0, driftRate: 0 };
  }

  let interval = expectedIntervalMs;
  if (interval === undefined) {
    // Python: gaps_result.get('expected_interval', 20) —— 键恒存在
    //（空结果里也是 0），20 这个缺省值实际永远不会生效
    interval = calcInterPacketGaps(packets, ssrc).expectedInterval;
  }

  const drift: DriftSample[] = [];
  let offset = 0;
  for (let i = 1; i < pkts.length; i++) {
    const actualGap = (pkts[i].time - pkts[i - 1].time) * 1000;
    offset += actualGap - interval;
    drift.push({ time: pkts[i].time, offsetMs: offset });
  }

  const totalTime = pkts[pkts.length - 1].time - pkts[0].time;
  const driftRate = totalTime > 0 ? (offset / totalTime) * 1000 : 0; // ms/s

  return {
    drift: drift.map((d) => ({ time: d.time, offsetMs: roundPy(d.offsetMs, 2) })),
    totalDriftMs: roundPy(offset, 2),
    driftRate: roundPy(driftRate, 2),
  };
}

/**
 * 对比多个流的抖动情况。
 *
 * @param results {label: gap_result, ...}
 */
export function compareJitter(
  results: Record<string, InterPacketGapsResult | null>,
): JitterCompareResult {
  const comparison: JitterCompareItem[] = [];
  let worstLabel: string | null = null;
  let worstStd = 0;

  for (const [label, result] of Object.entries(results)) {
    if (!result || result.mean === 0) continue;
    comparison.push({
      label,
      mean: result.mean,
      median: result.median,
      std: result.std,
      abnormalCount: result.abnormalCount,
      expectedInterval: result.expectedInterval,
    });
    if (result.std > worstStd) {
      worstStd = result.std;
      worstLabel = label;
    }
  }

  return { comparison, worstLabel };
}
