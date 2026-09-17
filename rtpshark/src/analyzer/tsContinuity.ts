// RTP 时间戳连续性检测器（ts_continuity.py 的 TS 移植）
// 检查 RTP 时间戳的跳变、倒退、重复与 32 位回绕。
//
// RTP 时间戳是发送端的媒体时钟：同一条流里按到达顺序它应单调递增，增量
// 等于每包携带的媒体时长（如 G.711 20ms 包化 = 增量 160 @ 8kHz）。以它为
// 基准可以区分：
//
// - ts 跳变（增量远超 seq 缺口能解释的媒体时间）：静音抑制（DTX）期间
//   发送端不发包、或发送端时间戳异常——此时 seq 连续、不算丢包；
// - ts 倒退：seq 同步倒退是网络乱序（迟到包），seq 前进而 ts 倒退是发送端
//   时间戳回退（严重异常）；
// - ts 重复（增量 0）：发送端异常或冗余重传；
// - ts 回绕：32 位计数器自然溢出，属正常现象，只计数不报事件。
//
// 本模块只检测与标注，不修改包数据；实测出的每包时长供音频重建替代
// "固定 160 样本"的假设。
import type { PacketMap } from './types';
import { getStreamPackets, signed32 } from './rtpParser';
import { getClockRate, AUDIO_PT } from './streamClassifier';

export const TS_MOD = 0x100000000; // 2^32
// 事件明细最多保留的条数（各类计数不受限，明细截断防止超大报告）
export const MAX_EVENTS = 50;
// seq 差值超过此值视为倒退（乱序）而非前进
export const SEQ_BACKWARD = 1 << 15;
export const SEQ_SPACE = 1 << 16;

export type TsEventKind = 'reorder' | 'ts_backward' | 'duplicate' | 'ts_jump';
export type TsContinuityMode = 'packet' | 'frame';

export interface TsContinuityEvent {
  time: number;
  kind: TsEventKind;
  seq: number;
  ts: number;
  // 异常处前后的包信息：供报告展示"前后相关内容"（点击展开
  // 逐包对照），让用户看到是哪两个包之间出了问题
  prevSeq: number;
  prevTs: number;
  tsDelta: number;
  mediaGapMs: number | null;
  arrivalGapMs: number;
}

export interface TsContinuityCheckResult {
  isContinuous: boolean; // 无任何异常事件
  packetCount: number;
  pt: number | null; // 主 PT（出现次数最多）
  clockRate: number | null; // 主 PT 的时钟率，未知 PT 为 null
  mode: TsContinuityMode | null; // 逐包核对（音频）/ 帧级核对（视频等）
  packetDurationMs: number | null; // 实测每包媒体时长
  medianTsDelta: number; // 实测时间戳增量中位数（ts 单位）
  wrapCount: number; // 32 位回绕次数（正常现象）
  eventCount: number; // 异常事件总数
  jumpCount: number; // ts 跳变（媒体时间缺口）
  backwardCount: number; // ts 倒退（seq 顺序时，发送端异常）
  reorderCount: number; // seq+ts 同步倒退（网络乱序）
  duplicateCount: number; // ts 重复（增量 0）
  totalMediaGapMs: number; // 跳变累计缺少的媒体时间
  mediaGapsMs: { time: number; gapMs: number }[];
  events: TsContinuityEvent[];
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

/** 中位数：偶数个取中间两数均值（等价 statistics.median） */
function medianOf(vals: number[]): number {
  const s = [...vals].sort((a, b) => a - b);
  const n = s.length;
  if (n === 0) return 0;
  if (n % 2 === 1) return s[(n - 1) / 2];
  return (s[n / 2 - 1] + s[n / 2]) / 2;
}

function emptyResult(): TsContinuityCheckResult {
  return {
    isContinuous: true,
    packetCount: 0,
    pt: null,
    clockRate: null,
    mode: null,
    packetDurationMs: null,
    medianTsDelta: 0,
    wrapCount: 0,
    eventCount: 0,
    jumpCount: 0,
    backwardCount: 0,
    reorderCount: 0,
    duplicateCount: 0,
    totalMediaGapMs: 0,
    mediaGapsMs: [],
    events: [],
  };
}

/**
 * 检测指定 SSRC 流的 RTP 时间戳连续性（按捕获时间序）。
 *
 * clockRate / fullMode：调用方已按 SDP/时钟率解析出流种类时直接传入
 * （动态 PT 音频如 OPUS@96 只看 PT 号会被当视频、时钟率也会取错）；缺省
 * 按静态 PT 表推断。
 */
export function checkTsContinuity(
  packets: PacketMap,
  ssrc: number,
  clockRate?: number | null,
  fullMode?: boolean | null,
): TsContinuityCheckResult {
  const pkts = getStreamPackets(packets, ssrc);
  const result = emptyResult();
  if (pkts.length < 2) return result;

  result.packetCount = pkts.length;
  // 主 PT = 出现次数最多的 PT（并列取先出现者，与 Counter.most_common 一致）
  const ptCounts = new Map<number, number>();
  for (const p of pkts) ptCounts.set(p.pt, (ptCounts.get(p.pt) || 0) + 1);
  let mainPt = pkts[0].pt;
  let bestCount = -1;
  for (const [p, c] of ptCounts) {
    if (c > bestCount) {
      bestCount = c;
      mainPt = p;
    }
  }
  result.pt = mainPt;
  let rate = clockRate ?? null;
  if (rate === null) rate = getClockRate(mainPt);
  result.clockRate = rate;

  // 检查模式：静态音频 PT 每包自带独立媒体时间，逐包核对；视频/动态 PT
  // 流一帧拆多个包、同帧时间戳相同（RFC 6184），DTMF 事件重传同样共用
  // 时间戳（RFC 4733）——这些流只查倒退/乱序/回绕，重复与逐包跳变不算
  // 异常，否则正常视频流会被刷爆告警
  let full: boolean;
  if (fullMode === undefined || fullMode === null) full = AUDIO_PT.has(mainPt);
  else full = fullMode;
  result.mode = full ? 'packet' : 'frame';

  // 第一遍：带符号的时间戳增量 → 中位数即实测每包时长（中位数对个别
  // 跳变和倒退稳健；负增量与 0 不参与）
  const deltas: number[] = [];
  for (let i = 1; i < pkts.length; i++) {
    deltas.push(signed32(pkts[i].rtpTs - pkts[i - 1].rtpTs));
  }
  const positive = deltas.filter((d) => d > 0);
  const medianDelta = positive.length ? Math.trunc(roundPy(medianOf(positive), 0)) : 0;
  result.medianTsDelta = medianDelta;
  if (full && rate && medianDelta > 0) {
    result.packetDurationMs = roundPy((medianDelta / rate) * 1000, 2);
  }

  const jumpThreshold = Math.max(Math.floor(medianDelta / 2), 1);
  const events = result.events;
  // 近期异常步累积的未弥补媒体时间（≤0）：重复/倒退的缺口由后续增量
  // 抵偿，避免"ts 持平一步、下一步 +320 追平"这类自愈行为被误报成跳变
  let pending = 0;

  for (let i = 1; i < pkts.length; i++) {
    const t = pkts[i].time;
    const seq = pkts[i].seq;
    const ts = pkts[i].rtpTs;
    const prevSeq = pkts[i - 1].seq;
    const prevTs = pkts[i - 1].rtpTs;
    const d = deltas[i - 1];
    const seqGap = (seq - prevSeq) & 0xffff;

    // 32 位回绕：原始值变小但带符号差值为正，属正常溢出
    if (ts < prevTs && d > 0) result.wrapCount += 1;

    // 非 main PT 包（如 RFC 4733 DTMF telephone-event：ts 为"事件起始"
    // 时刻、重传包重复同一 ts）时间戳语义与主媒体流不同，不参与倒退/
    // 重复/跳变判定——否则正常按键会被误报成发送端时钟异常
    if (full && (pkts[i].pt !== mainPt || pkts[i - 1].pt !== mainPt)) continue;

    let kind: TsEventKind | null = null;
    let tsDelta = 0;
    let mediaGapMs: number | null = null;
    if (d < 0) {
      if (seqGap >= SEQ_BACKWARD) {
        // 乱序：seq 同步倒退 k 步（迟到包），倒退的 k 步媒体时间会在
        // seq 重新越过时再次计入，抵偿按 k 步记。若按无符号 gap 算，
        // 抵偿变成 65535−k 步，pending 被打成巨负值，之后整条流的
        // 跳变检测全部失效（一次乱序就够）
        const k = SEQ_SPACE - seqGap;
        result.reorderCount += 1;
        kind = 'reorder';
        tsDelta = d;
        pending += d + k * medianDelta;
      } else {
        result.backwardCount += 1;
        kind = 'ts_backward';
        tsDelta = d;
        pending += d - seqGap * medianDelta;
      }
    } else if (d === 0) {
      if (full) {
        result.duplicateCount += 1;
        kind = 'duplicate';
        tsDelta = 0;
        pending -= medianDelta;
      }
    } else if (full && medianDelta > 0 && seqGap < SEQ_BACKWARD) {
      // 净推进 = 实际增量 - seq 间隔×每包时长 + 未弥补缺口；超出
      // 阈值的部分是 seq 无法解释的媒体时间缺口（静音抑制/发送端
      // 时间戳异常）
      const net = d - seqGap * medianDelta + pending;
      if (net > jumpThreshold) {
        result.jumpCount += 1;
        mediaGapMs = rate ? roundPy(((net / rate) * 1000), 1) : null;
        if (mediaGapMs !== null) {
          result.mediaGapsMs.push({ time: t, gapMs: mediaGapMs });
          result.totalMediaGapMs += mediaGapMs;
        }
        kind = 'ts_jump';
        tsDelta = d;
        pending = 0;
      } else {
        pending = Math.min(net, 0);
      }
    }

    if (kind !== null) {
      result.eventCount += 1;
      if (events.length < MAX_EVENTS) {
        events.push({
          time: t,
          kind,
          seq,
          ts,
          prevSeq,
          prevTs,
          tsDelta,
          mediaGapMs,
          arrivalGapMs: roundPy((t - pkts[i - 1].time) * 1000, 1),
        });
      }
    }
  }

  result.totalMediaGapMs = roundPy(result.totalMediaGapMs, 1);
  result.isContinuous = result.eventCount === 0;
  return result;
}
