// 静音/能量分析与无声诊断（silence_analyzer.py 的 TS 移植）
//
// "没听到声音"在 RTP 层面有五种成因，逐一对应检查（按媒体路径从源到汇）：
// 1. 发言端根本没发流（未接通/未采集/未开麦）——抓包里无该方向流；
// 2. 流发了但没到下一跳（NAT/防火墙/FS 未桥接）——发言端抓包有、FS 抓包无；
// 3. 包在路上丢光——逐抓包点丢包率（packet_loss 模块负责，这里引用结论）；
// 4. 包在但内容是静音——seq/ts 完全连续、零丢包，载荷却全是数字零：
//    静音键/采集故障。RTP 层面"完全正常"就是没声，这是最容易被漏掉的一层；
// 5. FS 收到了但没转发/转出静音——FS 入站流正常、FS→听者出站流缺失或静音。
//
// 能量统计按媒体时间加权而不是按包数：开静音抑制（DTX/VAD）的终端在静音
// 期间不发包，按包数统计会把"只有说话时才发包"误判成一直有人声；按时间戳
// 推进的媒体时间统计（未发包的缺口=静音）才能还原真实的人声占比。
//
// "有人声"还要排除稳态单频音（回铃音/忙音/提示音）：一声 450Hz 回铃音
// 能量再大也不是人声，不能把"只响了一声嘟之后全程静音"的流撑过门限
// 判成"有人声"——这正是单通抓包里最常见的形态。
//
// 桌面端适配：quality_analyzer 的帧级单频音检测（tone_intervals）与人声
// 包络判定（_voice_mask）按原参数在本模块内用纯 JS 重实现（自实现
// 256 点 FFT 替代 numpy），不引入新的 npm 依赖。
import type { CallInfo, Capture, PacketMap, RtpPacketRec } from './types';
import { signed32 } from './rtpParser';
import { getPtName, pickCallStream } from './streamClassifier';
import type { RtcpRrSummary, RtcpSummary } from './rtcpParser';
import { decodeG711 } from './mediaExtractor';
import type { CallParties } from './callDetector';

// 判定"有人声"的单包 RMS 门限（16bit 线性 PCM，≈ -36 dBFS）。
// G.711 静音帧解码后 RMS≈0，室内噪声通常 <300，正常说话 >1000
export const ACTIVE_RMS = 500;
export const SAMPLE_RATE = 8000; // G.711 采样率
// 有声媒体时间占比低于此值视为"基本没人说话"（全程静音=0）
export const SILENT_RATIO = 0.02;
// 单个时间戳缺口最多计入的静音媒体时间（秒）：时间戳重置不当作超长静音
export const MAX_GAP_S = 10.0;
// 说话/静音区间明细最多保留条数
export const MAX_SPANS = 40;

// ---------------- SilenceProfile ----------------

/** 说话/静音区间（捕获时间，秒，已合并） */
export interface SilenceSpan {
  start: number;
  end: number;
  active: boolean;
}

export type SilenceVerdict = 'normal' | 'sparse' | 'silent' | 'unknown';

/** analyze_silence 的结果：一条音频流的能量与静音画像 */
export interface SilenceProfile {
  packetCount: number;
  /** 解码用编码名 */
  codec: string;
  /** 仅 PCMU/PCMA 可解 */
  decodable: boolean;
  /** 有声媒体时间占比（含 DTX 缺口，已剔除提示音/单频音段） */
  activeRatio: number;
  /** 有声媒体时间 */
  speechMs: number;
  /** 有声+静音媒体时间（不含重置缺口） */
  mediaMs: number;
  /** 稳态单频音（提示音等）媒体时间 */
  toneMs: number;
  /** 活跃段包络起伏像人声？False=只有平稳背景电平（无话音） */
  speechActivity: boolean | null;
  /** 仅 speechActivity=False 或有人声但有 idle 段时存在：
   * 背景电平时长与电平值 */
  steadyEnergyMs?: number;
  steadyDbfs?: number;
  /** 解码后全零的包（数字静音） */
  zeroPackets: number;
  activePackets: number;
  /** 有人声的包平均电平 */
  meanActiveDbfs: number | null;
  peakDbfs: number | null;
  /** 流开始到第一声（null=全程无） */
  firstActiveS: number | null;
  /** 区间明细（捕获时间，合并后最多 MAX_SPANS 条） */
  spans: SilenceSpan[];
  spanCount: number;
  verdict: SilenceVerdict;
}

// ---------------- 帧级单频音检测参数（quality_analyzer 同一套） ----------------

const FRAME = 256; // 帧长 32ms @8kHz
const HOP = 128; // 帧移 16ms
const TONE_BAND_MIN = 250.0; // 啸叫检测频带（8k 采样奈奎斯特 4kHz）
const TONE_BAND_MAX = 3900.0;
const TONE_PROMINENCE = 40.0; // 谱峰 / 谱中位数 ≥40 倍才够"窄而尖"
const TONE_MIN_RMS = 300; // 帧能量下限（排除底噪里的伪峰）
const TONE_MIN_FRAMES = 10; // 持续 ≥10 帧（约 0.16s）判为持续单频音
const HUM_LOW_HZ = 220.0; // 低频嗡声的"低频段"上界
const HUM_RATIO = 0.85; // 低频能量占比门限
const HUM_MIN_RMS = 800; // 嗡声要有可闻电平
const HUM_MIN_FRAMES = 50; // 持续 ≥0.8s

// 人声包络判定参数（quality_analyzer._voice_mask 同一套）
// 人声包络起伏下限（变异系数）；实测人声 0.8-1.2，工频嗡声/平稳底噪 < 0.4
const SPEECH_CV = 0.5;
// 包络 p10/p50 下展门限：真实说话在音节间有明显的低谷
const SPEECH_SPREAD = 0.55;
// 平坦活跃段里，高于背景电平 1.8×（≈+5dB）且持续足够的突发按"人声时刻"计
const VOICE_ABOVE_FLOOR = 1.8;
// 突发至少持续 10 个统计样本（包 20ms/帧 16ms）
const VOICE_MIN_EPISODE = 10;

// ---------------- 256 点 FFT（numpy rfft 的等价实现） ----------------

const FFT_N = 256;
const FFT_BINS = FFT_N / 2 + 1; // 129 个 rfft bin
const DF = SAMPLE_RATE / FFT_N; // 频谱 bin 宽（Hz）
const HANN = new Float64Array(FFT_N);
for (let n = 0; n < FFT_N; n++) {
  HANN[n] = 0.5 - 0.5 * Math.cos((2 * Math.PI * n) / (FFT_N - 1));
}
const BITREV = (() => {
  const r = new Int32Array(FFT_N);
  let bits = 0;
  while (1 << bits < FFT_N) bits++;
  for (let i = 0; i < FFT_N; i++) {
    let x = i;
    let y = 0;
    for (let b = 0; b < bits; b++) {
      y = (y << 1) | (x & 1);
      x >>= 1;
    }
    r[i] = y;
  }
  return r;
})();
const TW_RE = new Float64Array(FFT_N / 2);
const TW_IM = new Float64Array(FFT_N / 2);
for (let k = 0; k < FFT_N / 2; k++) {
  TW_RE[k] = Math.cos((-2 * Math.PI * k) / FFT_N);
  TW_IM[k] = Math.sin((-2 * Math.PI * k) / FFT_N);
}

// 复用的工作缓冲（单线程顺序使用）
const FFT_RE = new Float64Array(FFT_N);
const FFT_IM = new Float64Array(FFT_N);
const MAG = new Float64Array(FFT_BINS);
const MEDBUF = new Float64Array(FFT_N - 1);

function fftInPlace(): void {
  for (let i = 0; i < FFT_N; i++) {
    const j = BITREV[i];
    if (j > i) {
      let t = FFT_RE[i]; FFT_RE[i] = FFT_RE[j]; FFT_RE[j] = t;
      t = FFT_IM[i]; FFT_IM[i] = FFT_IM[j]; FFT_IM[j] = t;
    }
  }
  for (let size = 2; size <= FFT_N; size <<= 1) {
    const half = size >> 1;
    const step = FFT_N / size;
    for (let i = 0; i < FFT_N; i += size) {
      for (let j = 0; j < half; j++) {
        const k = j * step;
        const aRe = FFT_RE[i + j];
        const aIm = FFT_IM[i + j];
        const bRe = FFT_RE[i + j + half];
        const bIm = FFT_IM[i + j + half];
        const tre = bRe * TW_RE[k] - bIm * TW_IM[k];
        const tim = bRe * TW_IM[k] + bIm * TW_RE[k];
        FFT_RE[i + j + half] = aRe - tre;
        FFT_IM[i + j + half] = aIm - tim;
        FFT_RE[i + j] = aRe + tre;
        FFT_IM[i + j] = aIm + tim;
      }
    }
  }
}

// ---------------- numpy 辅助的等价实现 ----------------

/** numpy 默认（linear 插值）百分位数，输入需已升序 */
function percentileSorted(sorted: Float64Array, p: number): number {
  const n = sorted.length;
  if (n === 0) return 0;
  const rank = (p / 100) * (n - 1);
  const lo = Math.floor(rank);
  const hi = Math.min(lo + 1, n - 1);
  const frac = rank - lo;
  return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
}

/** 布尔数组的连续 True 段 [(start, length)] */
function boolRuns(mask: Uint8Array): [number, number][] {
  const out: [number, number][] = [];
  let start = -1;
  for (let i = 0; i < mask.length; i++) {
    if (mask[i] && start < 0) start = i;
    else if (!mask[i] && start >= 0) {
      out.push([start, i - start]);
      start = -1;
    }
  }
  if (start >= 0) out.push([start, mask.length - start]);
  return out;
}

/** 把布尔帧串成持续事件（[(start_t, end_t)]），1 帧空洞自动桥接 */
function trackRuns(
  flag: Uint8Array,
  frameT: Float64Array,
  minFrames: number,
): [number, number][] {
  const n = flag.length;
  const filled = Uint8Array.from(flag);
  for (let i = 1; i < n - 1; i++) {
    if (filled[i - 1] && filled[i + 1]) filled[i] = 1;
  }
  const merged: [number, number][] = [];
  for (const [start, length] of boolRuns(filled)) {
    if (length >= minFrames) {
      const s = frameT[start];
      const e = frameT[start + length - 1];
      if (merged.length && s - merged[merged.length - 1][1] <= (HOP / SAMPLE_RATE) * 4) {
        merged[merged.length - 1][1] = e;
      } else {
        merged.push([s, e]);
      }
    }
  }
  return merged;
}

/** 检测 PCM 中的稳态单频段（提示音/啸叫/低频嗡声），返回 [(start_s, end_s)]。
 * 帧级判定与 quality_analyzer 同一套参数（帧长、显著度、谐波豁免、
 * 低频占比），供静音分析把提示音从"有人声"时间里剔除——回铃音不是人声。 */
export function toneIntervals(x: Float64Array): [number, number][] {
  if (x.length < FRAME) return [];
  const nFrames = Math.floor((x.length - FRAME) / HOP) + 1;
  const isTone = new Uint8Array(nFrames);
  const isHum = new Uint8Array(nFrames);
  const frameT = new Float64Array(nFrames);
  const bandLo = Math.ceil(TONE_BAND_MIN / DF); // 250Hz
  const bandHi = Math.floor(TONE_BAND_MAX / DF); // 3900Hz
  const lowHi = Math.floor(HUM_LOW_HZ / DF); // 220Hz

  for (let f = 0; f < nFrames; f++) {
    const off = f * HOP;
    let sumSq = 0;
    for (let n = 0; n < FRAME; n++) {
      const v = x[off + n];
      sumSq += v * v;
      FFT_RE[n] = v * HANN[n];
      FFT_IM[n] = 0;
    }
    const frameRms = Math.sqrt(sumSq / FRAME);
    frameT[f] = (off + FRAME / 2) / SAMPLE_RATE; // 帧中心媒体时间
    fftInPlace();

    let globalPeak = 0; // 全谱（除直流）最大分量
    let sumAll = 0; // bins 1..128 总和
    let lowEnergy = 0; // 低频段（≤220Hz，除直流）能量
    for (let k = 0; k < FFT_BINS; k++) {
      MAG[k] = Math.sqrt(FFT_RE[k] * FFT_RE[k] + FFT_IM[k] * FFT_IM[k]);
      if (k >= 1) {
        sumAll += MAG[k];
        if (MAG[k] > globalPeak) globalPeak = MAG[k];
        if (k <= lowHi) lowEnergy += MAG[k];
      }
    }
    // 直流主导的帧（恒定电平信号）不是振荡，不能按单频音/嗡声判定
    const dcDom = MAG[0] > sumAll;

    // 带内谱峰
    let peakVal = 0;
    let peakBin = bandLo;
    for (let k = bandLo; k <= bandHi; k++) {
      if (MAG[k] > peakVal) {
        peakVal = MAG[k];
        peakBin = k;
      }
    }
    // 谱中位数（bins 1..128）
    for (let k = 1; k < FFT_BINS; k++) MEDBUF[k - 1] = MAG[k];
    MEDBUF.sort();
    const nMed = MEDBUF.length;
    const med = Math.max((MEDBUF[nMed / 2 - 1] + MEDBUF[nMed / 2]) / 2, 1e-6);
    const peakFreq = peakBin * DF;

    // 谱峰的 2f/3f/f÷2 处也有显著峰 → 是语音谐波结构，不是纯单频
    let harm = false;
    for (const mult of [2.0, 3.0, 0.5]) {
      const tgt = Math.round((peakFreq * mult) / DF);
      if (tgt >= 1 && tgt < FFT_BINS) {
        const lo = Math.max(tgt - 1, 0);
        const hi = Math.min(tgt + 1, FFT_BINS - 1);
        const mag = Math.max(MAG[tgt], MAG[lo], MAG[hi]);
        if (mag > 0.25 * peakVal) {
          harm = true;
          break;
        }
      }
    }

    isTone[f] =
      peakVal / med >= TONE_PROMINENCE &&
      peakVal >= globalPeak &&
      frameRms >= TONE_MIN_RMS &&
      !harm &&
      !dcDom
        ? 1
        : 0;
    isHum[f] =
      lowEnergy / Math.max(sumAll, 1e-9) >= HUM_RATIO &&
      frameRms >= HUM_MIN_RMS &&
      !dcDom
        ? 1
        : 0;
  }

  const iv = trackRuns(isTone, frameT, TONE_MIN_FRAMES);
  const hum = trackRuns(isHum, frameT, HUM_MIN_FRAMES);
  const all = [...iv, ...hum];
  all.sort((a, b) => a[0] - b[0]);
  const round3 = (v: number) => Math.round(v * 1000) / 1000;
  return all.map(([a, b]) => [round3(a), round3(b)] as [number, number]);
}

/** 活跃样本中哪些属于人声（其余为平稳背景电平）。返回 null=样本太少。
 * 分层判定，防止两种相反的漏报：
 * 1) 样本 <25（约 0.5s）→ 无法判定；
 * 2) 包络整体起伏大（cv ≥0.5，或低谷明显 p10/p50 ≤0.55）→ 全部按
 *    人声——正常说话的形态；
 * 3) 包络整体平（设备把背景电平整通发上来的形态）→ 高于背景电平
 *    1.8×且持续 ≥10 样本的突发单独算人声时刻。 */
export function voiceMask(rmsSeq: number[] | null): boolean[] | null {
  if (!rmsSeq || rmsSeq.length < 25) return null;
  const n = rmsSeq.length;
  // 5 点滑动平均（numpy 'same' 卷积：边缘按零填充后除以固定核长 5）
  const env = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    let s = 0;
    for (let j = Math.max(0, i - 2); j <= Math.min(n - 1, i + 2); j++) s += rmsSeq[j];
    env[i] = s / 5;
  }
  let mean = 0;
  for (let i = 0; i < n; i++) mean += env[i];
  mean /= n;
  let variance = 0;
  for (let i = 0; i < n; i++) variance += (env[i] - mean) * (env[i] - mean);
  variance /= n;
  const cv = Math.sqrt(variance) / Math.max(mean, 1e-9);
  const sortedEnv = Float64Array.from(env).sort();
  const p50 = Math.max(percentileSorted(sortedEnv, 50), 1e-9);
  const spread = percentileSorted(sortedEnv, 10) / p50;
  if (cv >= SPEECH_CV || spread <= SPEECH_SPREAD) {
    return new Array<boolean>(n).fill(true);
  }
  const thr = p50 * VOICE_ABOVE_FLOOR;
  const mask: boolean[] = [];
  for (let i = 0; i < n; i++) mask.push(env[i] >= thr);
  for (const [s, length] of boolRuns(Uint8Array.from(mask, (v) => (v ? 1 : 0)))) {
    if (length < VOICE_MIN_EPISODE) {
      for (let i = s; i < s + length; i++) mask[i] = false;
    }
  }
  return mask;
}

function dbfs(rms: number): number {
  return 20 * Math.log10(Math.max(rms, 1) / 32768);
}

const round1 = (x: number) => Math.round(x * 10) / 10;
const round2 = (x: number) => Math.round(x * 100) / 100;

// ---------------- analyze_silence ----------------

export function analyzeSilence(packets: PacketMap, ssrc: number): SilenceProfile {
  const result: SilenceProfile = {
    packetCount: 0, codec: 'unknown', decodable: false,
    activeRatio: 0.0, speechMs: 0.0, mediaMs: 0.0,
    toneMs: 0.0, speechActivity: null, zeroPackets: 0, activePackets: 0,
    meanActiveDbfs: null, peakDbfs: null, firstActiveS: null,
    spans: [], spanCount: 0, verdict: 'unknown',
  };

  const stream = new Map<number, RtpPacketRec>();
  const bySeq = packets.get(ssrc);
  if (bySeq) {
    for (const [seq, v] of bySeq) {
      if (v.payload !== undefined) stream.set(seq, v);
    }
  }
  if (!stream.size) return result;

  // 出现最多的 PT（并列取先见者，与 Python max(counts, key=…) 一致）
  const ptCounts = new Map<number, number>();
  let pt = 0;
  let ptBest = -1;
  for (const v of stream.values()) {
    const n = (ptCounts.get(v.pt) ?? 0) + 1;
    ptCounts.set(v.pt, n);
    if (n > ptBest) {
      ptBest = n;
      pt = v.pt;
    }
  }
  result.packetCount = stream.size;
  result.codec = getPtName(pt);
  result.decodable = pt === 0 || pt === 8;
  if (!result.decodable) return result;

  const seqs = [...stream.keys()].sort((a, b) => a - b);

  // 每包时长以时间戳增量中位数为准（包化不一定是 20ms/160 样本）
  const deltas: number[] = [];
  for (let i = 1; i < seqs.length; i++) {
    const d = signed32(stream.get(seqs[i])!.rtpTs - stream.get(seqs[i - 1])!.rtpTs);
    if (d > 0) deltas.push(d);
  }
  deltas.sort((a, b) => a - b);
  let spp = deltas.length ? deltas[Math.floor(deltas.length / 2)] : 0;
  if (!(spp > 0 && spp <= SAMPLE_RATE / 2)) spp = 160;

  // —— 第一遍：逐包解码取能量，并按媒体时间拼接 PCM（DTX 缺口补零，
  // 与真实播放时间对齐），供稳态单频音（提示音）剔除做帧级检测 ——
  const pktT: number[] = [];
  const pktTs: number[] = [];
  const pktRms: number[] = [];
  const mediaPos: number[] = []; // 每包在媒体时间轴上的起始样本位置
  const pcmChunks: Float64Array[] = [];
  let pos = 0;
  let prevTs: number | null = null;
  let peak = 0;
  let zeroPackets = 0;
  for (const seq of seqs) {
    const pkt = stream.get(seq)!;
    const t = pkt.time;
    const ts = pkt.rtpTs;
    if (prevTs !== null) {
      const gap = signed32(ts - prevTs) - spp;
      if (gap > 0 && gap <= MAX_GAP_S * SAMPLE_RATE) {
        pos += gap;
        pcmChunks.push(new Float64Array(gap));
      }
    }
    prevTs = ts;
    mediaPos.push(pos);
    if (pkt.pt !== pt) {
      // 非主 PT（如 CN 舒适噪声 PT 13）：按一包静音计
      pktRms.push(0);
      pcmChunks.push(new Float64Array(spp));
    } else {
      const lin = decodeG711(pkt.payload as Uint8Array, pt);
      let sumSq = 0;
      for (let i = 0; i < lin.length; i++) sumSq += lin[i] * lin[i];
      // audioop.rms 的截断语义（PyLong_FromDouble）
      const rms = lin.length ? Math.floor(Math.sqrt(sumSq / lin.length)) : 0;
      peak = Math.max(peak, rms);
      if (rms === 0) zeroPackets += 1;
      pktRms.push(rms);
      pcmChunks.push(Float64Array.from(lin));
    }
    pktT.push(t);
    pktTs.push(ts);
    pos += spp;
  }

  // —— 提示音剔除：稳态单频段（回铃音/忙音/啸叫/嗡声）不是人声 ——
  // 一声 450Hz 回铃音能量再大也不能把"之后全程静音"的流判成有人声
  let toneIv: [number, number][] = [];
  try {
    let totalLen = 0;
    for (const c of pcmChunks) totalLen += c.length;
    const xAll = new Float64Array(totalLen);
    let off = 0;
    for (const c of pcmChunks) {
      xAll.set(c, off);
      off += c.length;
    }
    toneIv = toneIntervals(xAll);
  } catch {
    toneIv = [];
  }

  const toneOverlap = (i: number): number => {
    // 第 i 包与单频音段重叠的样本数（段边缘留一个 FFT 帧余量）
    const s = mediaPos[i];
    const e = mediaPos[i] + spp;
    let ov = 0;
    for (const [a, b] of toneIv) { // 已按起始时间排序
      // 事件时间是帧中心时间（有 ±半帧量化误差），加上帧窗口本身
      // 覆盖信号起振的模糊，余量取一个整帧
      const lo = Math.trunc(a * SAMPLE_RATE) - FRAME;
      const hi = Math.trunc(b * SAMPLE_RATE) + FRAME;
      if (hi <= s) continue;
      if (lo >= e) break;
      ov += Math.min(hi, e) - Math.max(lo, s);
    }
    return ov;
  };

  let isActive: boolean[] = pktRms.map((rms, i) => rms >= ACTIVE_RMS && toneOverlap(i) < spp / 4);

  // —— 语音活动判定：有能量 ≠ 有人声 ——
  // 设备故障时会把持续背景电平（供电干扰/环境噪声）整通发过来，包
  // 能量同样过门限，"有声占比"会虚高。voiceMask 在活跃包里分出
  // 人声：整体起伏像人声就全算；整体平则只保留明显高于背景电平的
  // 突发段（"背景音里的人声时刻"），其余记为背景电平时间
  const actPos: number[] = [];
  isActive.forEach((act, i) => {
    if (act) actPos.push(i);
  });
  const vmask = voiceMask(actPos.map((i) => pktRms[i]));
  let steadyMs: number | undefined;
  let steadyDbfs: number | undefined;
  let speechActivity: boolean | null;
  if (vmask === null) {
    speechActivity = null;
  } else if (!vmask.some((v) => v)) {
    // 活跃能量全是平稳背景电平：不计入人声时间
    speechActivity = false;
    steadyMs = round1(((actPos.length * spp) / SAMPLE_RATE) * 1000);
    const sum = actPos.reduce((s, i) => s + pktRms[i], 0);
    steadyDbfs = round1(dbfs(sum / Math.max(actPos.length, 1)));
    isActive = pktRms.map(() => false);
  } else {
    speechActivity = true;
    const keep = new Set<number>();
    actPos.forEach((idx, j) => {
      if (vmask[j]) keep.add(idx);
    });
    const idle = actPos.filter((i) => !keep.has(i));
    if (idle.length) {
      steadyMs = round1(((idle.length * spp) / SAMPLE_RATE) * 1000);
      const sum = idle.reduce((s, i) => s + pktRms[i], 0);
      steadyDbfs = round1(dbfs(sum / idle.length));
    }
    isActive = pktRms.map((_, i) => keep.has(i));
  }

  // —— 第二遍：按剔除后的判定累计媒体时间与区间 ——
  let speechSamples = 0;
  let silentSamples = 0;
  const spans: SilenceSpan[] = [];
  let firstActive: number | null = null;
  const activeRmsVals: number[] = [];
  for (let i = 0; i < pktTs.length; i++) {
    if (i) {
      const gap = signed32(pktTs[i] - pktTs[i - 1]) - spp;
      if (gap > 0 && gap <= MAX_GAP_S * SAMPLE_RATE) silentSamples += gap;
    }

    if (isActive[i]) {
      speechSamples += spp;
      activeRmsVals.push(pktRms[i]);
      if (firstActive === null) firstActive = pktT[i];
    } else {
      silentSamples += spp;
    }

    const last = spans[spans.length - 1];
    if (last && last.active === isActive[i]) last.end = pktT[i];
    else spans.push({ start: pktT[i], end: pktT[i], active: isActive[i] });
  }

  result.zeroPackets = zeroPackets;
  result.activePackets = isActive.filter(Boolean).length;
  result.toneMs = round1(toneIv.reduce((s, [a, b]) => s + (b - a), 0) * 1000);
  result.speechActivity = speechActivity;
  if (steadyMs !== undefined) {
    result.steadyEnergyMs = steadyMs;
    result.steadyDbfs = steadyDbfs;
  }
  const total = speechSamples + silentSamples;
  result.speechMs = round1((speechSamples / SAMPLE_RATE) * 1000);
  result.mediaMs = round1((total / SAMPLE_RATE) * 1000);
  result.activeRatio = total ? Math.round((speechSamples / total) * 10000) / 10000 : 0.0;
  if (activeRmsVals.length) {
    result.meanActiveDbfs = round1(
      dbfs(activeRmsVals.reduce((a, b) => a + b, 0) / activeRmsVals.length),
    );
  }
  if (peak) result.peakDbfs = round1(dbfs(peak));
  if (firstActive !== null) {
    result.firstActiveS = round1(firstActive - stream.get(seqs[0])!.time);
  }

  const merged: SilenceSpan[] = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && last.active === s.active && s.start - last.end < 0.5) last.end = s.end;
    else merged.push({ ...s });
  }
  result.spanCount = merged.length;
  result.spans = merged.slice(0, MAX_SPANS).map((s) => ({
    start: round2(s.start),
    end: round2(s.end),
    active: s.active,
  }));

  const ratio = result.activeRatio;
  result.verdict =
    ratio >= SILENT_RATIO ? 'normal' : ratio > 0 ? 'sparse' : 'silent';
  return result;
}

// ---------------- 无声方向诊断 ----------------

export type LegStatus =
  | 'ok'
  | 'unknown'
  | 'silent_path'
  | 'silent_source'
  | 'blocked'
  | 'no_source';

// 方向判定优先级：数值越大问题越严重（用于单腿状态兜底排序）
const VERDICT_ORDER: Record<LegStatus, number> = {
  ok: 0, unknown: 1, silent_path: 2, silent_source: 3, blocked: 4, no_source: 5,
};

const VERDICT_TEXT: Record<LegStatus, string> = {
  ok: '媒体链路正常：发声端发出的流各段都存在且有人声',
  unknown: '数据不足，无法判定该方向（缺对应抓包点或编码不可解）',
  blocked: '媒体流在路径中断裂（单通最常见成因：NAT/防火墙/FS 未桥接转发）',
  silent_source:
    '发声端发出的就是静音：包在发、时间戳正常，但内容无人声（静音键/采集故障）',
  silent_path:
    '听者收到的是静音：链路中某一段把人声换成了静音（常见：发声端静音键/' +
    '采集故障，或 FS 转码/混音问题），具体见各腿备注',
  no_source: '该方向没有发现任何音频流（未发声/未接通）',
};

const ROLE_DISPLAY: Record<string, string> = {
  terminal: '主叫',
  seat: '被叫',
  fs: 'FS',
};

/** 一条腿的能量画像条目（源端/下一跳各一份） */
export interface LegProfileEntry {
  side: 'source' | 'next';
  role: string;
  profile: SilenceProfile;
}

/** 一条腿（源端 → 下一跳）的判定结果 */
export interface DiagnoseLeg {
  leg: string;
  ssrc: string | null;
  kind: 'leg';
  status: LegStatus;
  presence: { sentAtSource: boolean | null; arrivedAtNext: boolean | null };
  profiles: SilenceProfile[];
  rr: RtcpRrSummary | null;
  note: string;
}

/** 一个方向（speaker → listener）的诊断结论 */
export interface DiagnoseDirection {
  label: string;
  speaker: string;
  listener: string;
  verdict: LegStatus;
  verdictText: string;
  legs: DiagnoseLeg[];
}

export interface DiagnoseResult {
  available: boolean;
  p2p: boolean;
  directions: DiagnoseDirection[];
  summary: string;
}

/** CallInfo 缺失的可选字段（局部扩展，不改 types.ts）：
 * Python 版通话对象带 is_p2p */
export type DiagnoseCall = CallInfo & { isP2p?: boolean };

interface DirectionSpec {
  speakerRole: string;
  listenerRole: string;
  speakerIp: string | null;
  listenerIp: string | null;
  speakerName: string;
  listenerName: string;
}

interface CapEntry {
  role: string;
  cap: Capture;
}

/** silenceProfiles 的键格式：`${role}:${ssrc}`（Python 版为 (role, ssrc) 元组） */
export const silenceProfileKey = (role: string, ssrc: number): string => `${role}:${ssrc}`;

// CallParties（并行模块 callDetector.ts）字段直接可用：
// callerIp / callerIdent / answererIp / answererIdent

/** 按通话的两个方向做无声诊断（diagnose_audio 的移植）。
 * rtcpByRole：{role: summarizeRtcp 结果}，听者的 RTCP RR 是"听者视角收到
 * 什么"的佐证。parties：CallParties（SIP 识别的双方 IP），可选；缺失时
 * 无法从 FS 抓包兜底选流。 */
export function diagnoseAudio(
  canonCaptures: Record<string, Capture>,
  call: DiagnoseCall,
  serverIp: string | null,
  silenceProfiles: Record<string, SilenceProfile>,
  rtcpByRole: Record<string, RtcpSummary> = {},
  parties: CallParties | null = null,
): DiagnoseResult {
  const callSsrcs = new Set(call.ssrcs || []);
  const fsCap: CapEntry | null = canonCaptures['fs']
    ? { role: 'fs', cap: canonCaptures['fs'] }
    : canonCaptures['FS']
      ? { role: 'FS', cap: canonCaptures['FS'] }
      : null;
  const p2p = !!call.isP2p;
  const pp = parties ?? null;

  // 两个方向：主叫(terminal)→坐席(seat)、坐席→主叫
  const specs: DirectionSpec[] = [];
  for (const [speakerRole, listenerRole] of [
    ['terminal', 'seat'],
    ['seat', 'terminal'],
  ] as const) {
    specs.push({
      speakerRole,
      listenerRole,
      speakerIp: pp?.callerIp ?? null,
      listenerIp: pp?.answererIp ?? null,
      speakerName: speakerRole === 'terminal' ? '主叫' : '被叫',
      listenerName: listenerRole === 'seat' ? '被叫' : '主叫',
    });
  }

  const directions: DiagnoseDirection[] = [];
  let anyData = false;
  for (const spec of specs) {
    const spkCap: CapEntry | null = canonCaptures[spec.speakerRole]
      ? { role: spec.speakerRole, cap: canonCaptures[spec.speakerRole] }
      : null;
    const lstCap: CapEntry | null = canonCaptures[spec.listenerRole]
      ? { role: spec.listenerRole, cap: canonCaptures[spec.listenerRole] }
      : null;
    if (!spkCap && !lstCap && !fsCap) continue;
    const d = diagnoseDirection(
      spkCap, lstCap, fsCap, callSsrcs, serverIp, p2p,
      silenceProfiles, rtcpByRole, spec,
    );
    if (d) {
      directions.push(d);
      if (d.verdict !== 'unknown') anyData = true;
    }
  }

  if (!directions.length || !anyData) {
    return {
      available: false, p2p, directions,
      summary: '抓包数据不足，无法做无声方向诊断（需至少一个端点抓包；FS 抓包可补全链路）',
    };
  }

  const bad = directions.filter((d) => d.verdict !== 'ok');
  const summary = bad.length
    ? bad.map((d) => `${d.label}：${d.verdictText}`).join('；')
    : '两个方向的音频链路均正常（各段流都存在且有人声）';
  return { available: true, p2p, directions, summary };
}

/** 诊断一个方向（speaker→listener）。完全无数据时返回 null。 */
function diagnoseDirection(
  spkCap: CapEntry | null,
  lstCap: CapEntry | null,
  fsCap: CapEntry | null,
  callSsrcs: Set<number>,
  serverIp: string | null,
  p2p: boolean,
  profiles: Record<string, SilenceProfile>,
  rtcpByRole: Record<string, RtcpSummary>,
  spec: DirectionSpec,
): DiagnoseDirection | null {
  const speakerRole = spec.speakerRole;
  const listenerRole = spec.listenerRole;
  const peerOfSpeaker = p2p ? spec.listenerIp : serverIp;
  const peerOfListener = p2p ? spec.speakerIp : serverIp;
  const ssrcList = [...callSsrcs];

  // —— 选流 ——
  // 上行流：优先从发言端抓包选（最靠近源头），FS 抓包按发言端 IP 兜底
  let uplink: number | null = null;
  let uplinkAt: string | null = null;
  if (spkCap && peerOfSpeaker) {
    uplink = pickCallStream(spkCap.cap, ssrcList, null, peerOfSpeaker);
    uplinkAt = speakerRole;
  }
  if (uplink === null && fsCap && spec.speakerIp) {
    uplink = pickCallStream(fsCap.cap, ssrcList, spec.speakerIp, null);
    uplinkAt = 'fs';
  }
  // 下行流：优先从听者抓包选（最靠近汇），FS 抓包按听者 IP 兜底
  let downlink: number | null = null;
  let downlinkAt: string | null = null;
  if (lstCap && peerOfListener) {
    downlink = pickCallStream(lstCap.cap, ssrcList, peerOfListener, null);
    downlinkAt = listenerRole;
  }
  if (downlink === null && fsCap && spec.listenerIp) {
    downlink = pickCallStream(fsCap.cap, ssrcList, null, spec.listenerIp);
    downlinkAt = 'fs';
  }

  if (uplink === null && downlink === null) {
    return null; // 该方向一条流都没见到（含抓包缺失），无可诊断
  }

  let legs: DiagnoseLeg[];
  if (p2p) {
    legs = [
      judgeLeg(
        `直连（${spec.speakerName} → ${spec.listenerName}）`,
        uplink, uplinkAt, downlink, downlinkAt,
        spkCap, lstCap, profiles, rtcpByRole, speakerRole, listenerRole,
      ),
    ];
  } else {
    legs = [
      judgeLeg(
        `${spec.speakerName}上行（${spec.speakerName} → FS）`,
        uplink, uplinkAt, null, null,
        spkCap, fsCap, profiles, rtcpByRole, speakerRole, listenerRole,
      ),
      judgeLeg(
        `${spec.listenerName}下行（FS → ${spec.listenerName}）`,
        null, null, downlink, downlinkAt,
        fsCap, lstCap, profiles, rtcpByRole, speakerRole, listenerRole,
      ),
    ];
  }

  // 方向级判定按"路径顺序"归并，不是简单取最严重：
  // 上行腿就断了 → 断裂；源头没发声 → 无源；下行缺流但上行在发 →
  // 是 FS 没转发出去（也归为断裂）；再按静音归属
  let verdict: LegStatus;
  if (p2p) {
    verdict = legs[0].status;
  } else {
    const up = legs[0].status;
    const down = legs[legs.length - 1].status;
    const statuses = [up, down];
    if (statuses.includes('blocked')) {
      verdict = 'blocked';
    } else if (up === 'no_source') {
      verdict = 'no_source';
    } else if (down === 'no_source') {
      // 上行在发、FS 侧没有对应的下行流：FS 未桥接转发
      verdict = 'blocked';
    } else if (statuses.includes('silent_source')) {
      verdict = 'silent_source';
    } else if (statuses.includes('silent_path')) {
      verdict = 'silent_path';
    } else {
      verdict = statuses.reduce((a, b) => (VERDICT_ORDER[b] > VERDICT_ORDER[a] ? b : a));
    }
  }

  const label = `${spec.speakerName} → ${spec.listenerName}`;
  let text = VERDICT_TEXT[verdict];
  if (verdict === 'blocked') {
    // 常规断裂列出 blocked 腿；FS 未转发（下行 no_source）时列出该腿
    const dead =
      legs.filter((l) => l.status === 'blocked').map((l) => l.leg).length
        ? legs.filter((l) => l.status === 'blocked').map((l) => l.leg)
        : legs.filter((l) => l.status === 'no_source').map((l) => l.leg);
    text += `——断裂点：${dead.join('、')}`;
  }
  return {
    label, speaker: spec.speakerName, listener: spec.listenerName,
    verdict, verdictText: text, legs,
  };
}

/** 一条腿的判定：流在源端有没有发、到没到下一跳、各点能量如何。
 * uplink / p2p 腿：srcSsrc=源端发现的流；downlink 腿：dstSsrc=听者端
 * 发现的流。两侧 SSRC 本是同一条媒体（经 FS 时换成下行新 SSRC），这里
 * 按"源端发出的"与"下一跳到达的"分别取能量画像。 */
function judgeLeg(
  legName: string,
  srcSsrc: number | null,
  srcAt: string | null,
  dstSsrc: number | null,
  _dstAt: string | null, // 与 Python _judge_leg 签名对齐（原版未使用）
  srcCap: CapEntry | null,
  dstCap: CapEntry | null,
  profiles: Record<string, SilenceProfile>,
  rtcpByRole: Record<string, RtcpSummary>,
  speakerRole: string,
  listenerRole: string,
): DiagnoseLeg {
  const ssrc = srcSsrc !== null ? srcSsrc : dstSsrc;
  const presence = { sentAtSource: null as boolean | null, arrivedAtNext: null as boolean | null };
  const notes: string[] = [];
  if (ssrc === null) {
    // 该腿没有可认定的流：源端抓包在场 → 真没发；源端抓包缺失 → 无法确认
    const status: LegStatus = srcCap ? 'no_source' : 'unknown';
    const note = status === 'no_source'
      ? '该方向未发现音频流（未发声/未接通）'
      : '未发现该方向的音频流（源端抓包缺失，无法确认是否发声）';
    return { leg: legName, ssrc: null, kind: 'leg', status, presence, profiles: [], rr: null, note };
  }

  const ssrcHex = `0x${(ssrc >>> 0).toString(16).padStart(8, '0')}`;
  presence.sentAtSource = srcCap ? ssrc in srcCap.cap.streams : null;
  presence.arrivedAtNext = dstCap ? ssrc in dstCap.cap.streams : null;
  const sent = presence.sentAtSource;
  const arrived = presence.arrivedAtNext;

  // 能量画像：源端（发了什么）与下一跳（收到了什么）各取一份
  const sideProfiles: LegProfileEntry[] = [];
  for (const [side, cap] of [
    ['source', srcCap],
    ['next', dstCap],
  ] as const) {
    if (!cap) continue;
    const p = profiles[`${cap.role}:${ssrc}`];
    if (p && p.packetCount) {
      sideProfiles.push({ side, role: cap.role, profile: p });
    }
  }

  let status: LegStatus = 'unknown';
  if (sent === true && arrived === false) {
    status = 'blocked';
    notes.push('源端在发、下一跳抓包未见到达（网络/NAT 断裂，或下一跳抓包未覆盖该时段）');
  } else if (sent === false && arrived === true) {
    notes.push('下一跳在收、源端抓包未见发出（源端抓包时段缺口，发送本身正常）');
  }

  const srcP = sideProfiles.find((e) => e.side === 'source') ?? null;
  const nextP = sideProfiles.find((e) => e.side === 'next') ?? null;
  const srcV = srcP ? srcP.profile.verdict : null;
  const nextV = nextP ? nextP.profile.verdict : null;

  // 某侧抓包缺该流/画像为空时 entry 为 null，只描述存在的一侧
  if (srcP) notes.push(describeProfile(srcP));
  if (nextP) notes.push(describeProfile(nextP));

  // 静音归属：srcAt 是端点角色时可直接断言"发声端发的是静音"；源端是
  // FS 中转视角（srcAt 为 None/'fs'）时无法确认发声端，归为途中并备注
  if (srcV === 'silent' && (srcAt === speakerRole || srcAt === listenerRole)) {
    status = 'silent_source';
    notes.push('静音源头在发声端：发出即静音（静音键/采集故障）');
  } else if (srcV === 'silent' || nextV === 'silent') {
    if (status === 'unknown') status = 'silent_path';
    if (srcV === 'normal') {
      notes.push('发声端有声、下一跳收到静音：静音产生于这段链路');
    } else {
      notes.push('本段链路为静音（未直接观测到发声端能量，静音可能来自发声端本身或其上游）');
    }
  } else if (srcV === 'normal' || srcV === 'sparse' || nextV === 'normal' || nextV === 'sparse') {
    if (status === 'unknown') status = 'ok';
  }
  // 全部 unknown 时保持 unknown

  // 接收端 RTCP RR 佐证（听者视角的丢包）
  let rr: RtcpRrSummary | null = null;
  const dstRole = dstCap ? dstCap.role : null;
  if (dstRole && rtcpByRole[dstRole]) {
    const cand = rtcpByRole[dstRole].rr[ssrc];
    if (cand) {
      rr = cand;
      if ((rr.fractionLostPct ?? 0) > 2) {
        notes.push(`接收端 RTCP RR 自报丢包 ${rr.fractionLostPct}%`);
      }
    }
  }

  return {
    leg: legName, ssrc: ssrcHex, kind: 'leg',
    status, presence,
    profiles: sideProfiles.map((e) => e.profile),
    rr, note: notes.join('；'),
  };
}

function describeProfile(entry: LegProfileEntry): string {
  const p = entry.profile;
  const role = ROLE_DISPLAY[entry.role] ?? entry.role;
  const tone = p.toneMs
    ? `，其中 ${(p.toneMs / 1000).toFixed(1)}s 为提示音/单频音已剔除`
    : '';
  const steady = p.steadyEnergyMs
    ? `；另有持续背景电平（约 ${p.steadyDbfs} dBFS，无说话起伏，疑似供电干扰/环境噪声）`
    : '';
  if (p.verdict === 'silent') {
    const zero = p.zeroPackets ? `，${p.zeroPackets} 包为数字零` : '';
    return `${role}侧实测全程无人声（有声占比 ${(p.activeRatio * 100).toFixed(1)}%${zero}${tone}${steady}）`;
  }
  if (p.verdict === 'sparse') {
    return `${role}侧仅 ${(p.activeRatio * 100).toFixed(1)}% 时间有人声（${(p.speechMs / 1000).toFixed(1)}s/${(p.mediaMs / 1000).toFixed(0)}s${tone}${steady}）`;
  }
  if (p.verdict === 'unknown') {
    return `${role}侧编码不可解（${p.codec}），无法判定能量`;
  }
  return `${role}侧实测有人声（占比 ${(p.activeRatio * 100).toFixed(1)}%，均值 ${p.meanActiveDbfs} dBFS${tone}${steady}）`;
}
