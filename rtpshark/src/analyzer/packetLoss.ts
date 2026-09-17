// 丢包检测器（packet_loss.py 的 TS 移植）
// 通过 RTP 序列号连续性检查丢包情况。
//
// 按捕获时间序维护 32 位扩展序号与"缺包集合"：seq 前进留下的缺口记为
// 待定丢包，迟到的乱序包补上缺口时退还，因此离线统计的丢包数是最终真实
// 值——乱序不再被回绕运算放大成六万多个"丢包"。乱序本身单独计数；静音
// 抑制（seq 连续但媒体时间断档）不由 seq 判定，由 ts_continuity 模块用
// 时间戳标注。
import type { PacketMap } from './types';
import { getStreamPackets } from './rtpParser';

// seq 差值超过此值视为倒退（乱序）而非前进
export const SEQ_BACKWARD = 1 << 15;
export const SEQ_SPACE = 1 << 16;

export interface LossEventPoint {
  time: number;
  count: number;
}

export interface PacketLossResult {
  totalPackets: number;
  totalLost: number;
  lossRatePct: number;
  /** 观察到的缺口（含后来被乱序包补上的，供定位时间点） */
  lossEvents: LossEventPoint[];
  lossEventCount: number;
  maxConsecutiveLoss: number;
  /** 乱序倒退次数（不计入丢包） */
  reorderCount: number;
  isClean: boolean;
}

export interface LabeledPacketLossResult extends PacketLossResult {
  label: string;
}

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

function emptyLossResult(): PacketLossResult {
  return {
    totalPackets: 0, totalLost: 0, lossRatePct: 0,
    lossEvents: [], lossEventCount: 0,
    maxConsecutiveLoss: 0, reorderCount: 0, isClean: true,
  };
}

/** 检测指定 SSRC 的丢包情况。 */
export function detectPacketLoss(packets: PacketMap, ssrc: number): PacketLossResult {
  const pkts = getStreamPackets(packets, ssrc);
  if (pkts.length < 2) return emptyLossResult();

  const lossEvents: LossEventPoint[] = [];
  let maxConsecutive = 0;
  let currentConsecutive = 0;
  let reorderCount = 0;
  const missing = new Set<number>(); // 扩展序号空间里尚未到达的包

  const first = pkts[0];
  let prevSeq = first.seq;
  let prevExt = prevSeq;
  let cycles = 0;
  for (let i = 1; i < pkts.length; i++) {
    const { time, seq } = pkts[i];
    const d = (seq - prevSeq) & (SEQ_SPACE - 1);
    if (d === 0) continue; // 同一 (ssrc, seq) 在提取时已去重，防御性跳过
    if (d < SEQ_BACKWARD) {
      // 前进（可能越过 65535→0 回绕）
      if (seq < prevSeq) cycles += 1;
      const ext = seq + cycles * SEQ_SPACE;
      const gap = ext - prevExt - 1;
      if (gap > 0) {
        for (let m = prevExt + 1; m < ext; m++) missing.add(m);
        lossEvents.push({ time, count: gap });
        currentConsecutive += gap;
        maxConsecutive = Math.max(maxConsecutive, gap);
      }
      prevSeq = seq;
      prevExt = ext;
    } else {
      // 倒退 = 迟到的乱序包：若它在此前的缺口里，退还多记的丢包
      const ext = seq + cycles * SEQ_SPACE;
      if (missing.has(ext)) {
        missing.delete(ext);
      } else if (missing.has(ext - SEQ_SPACE)) {
        // 回绕边界附近的乱序：缺包记录在上一圈
        missing.delete(ext - SEQ_SPACE);
      }
      reorderCount += 1;
      currentConsecutive = 0;
    }
  }

  const totalLost = missing.size;
  const total = pkts.length + totalLost;
  const lossRate = total > 0 ? (totalLost / total) * 100 : 0;

  return {
    totalPackets: pkts.length,
    totalLost,
    lossRatePct: roundPy(lossRate, 4),
    lossEvents,
    lossEventCount: lossEvents.length,
    maxConsecutiveLoss: maxConsecutive,
    reorderCount,
    isClean: totalLost === 0,
  };
}

/**
 * 批量检测多个 SSRC 的丢包。
 *
 * @param packets RTP 包字典
 * @param ssrcs   要检测的 SSRC 列表
 * @param labels  {ssrc: label} 可选标签
 */
export function detectAllLosses(
  packets: PacketMap,
  ssrcs: number[],
  labels?: Record<number, string>,
): Record<number, LabeledPacketLossResult> {
  const results: Record<number, LabeledPacketLossResult> = {};
  for (const ssrc of ssrcs) {
    const label = (labels && labels[ssrc] !== undefined)
      ? labels[ssrc]
      : `SSRC=0x${ssrc.toString(16).padStart(8, '0')}`;
    const result = detectPacketLoss(packets, ssrc);
    results[ssrc] = { ...result, label };
  }
  return results;
}
