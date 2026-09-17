// 音画质量异常分析（quality_analyzer.py 的 TS 移植）：杂音 / 啸叫 / 削波破音 / 底噪（音频）、花屏（视频）
//
// "有杂音、啸叫、花屏"类投诉在 RTP 抓包层面的可观测证据，逐一对应检测：
//
// 音频（仅 G.711 PCMU/PCMA 可解，解码流程与媒体重建一致；解码与 FFT 均在本文件内实现）：
// 1. 啸叫/持续单频音——帧级 FFT 找"又高又窄又稳定"的谱峰 + 谐波伙伴检查。
//    ≥250Hz 报啸叫/持续单频音；425/450Hz 等呼叫提示音频率上的短促单音
//    单独归为"提示音" info 项（正常呼叫流程音，不是啸叫）。
// 2. 低频嗡声（50/100Hz 电源干扰、地环路）——低频能量占比 ≥85% 且持续。
// 3. 削波破音——波形顶端被削平：连续多个采样值一字排开且幅度极大。
// 4. 爆点/咔哒声——孤立的脉冲尖峰：本身幅度极大而前后邻域都很小。
// 5. 底噪——静音帧（无话音）的电平中位数。
// 6. 音量——话音帧平均电平过低/过高。
// 7. RTP 序号/时间戳秩序——重建可信度的前提。
//
// 视频（RTP 层证据，H.264）：丢包→花屏映射（距下一 IDR 时长）、破损 NAL
// 计数（FU-A/STAP-A）、关键帧间隔。桌面端没有 ffmpeg：去掉解码校验与
// raw_path 依赖，结果里注明"无 ffmpeg 校验"。
//
// 事件时间均为"相对流第一个包捕获时刻"的秒数，与回放页对时使用。
import type { PacketMap } from './types';
import { getStreamPackets, signed32 } from './rtpParser';
import { getPtName } from './streamClassifier';

// ---------- 音频参数 ----------
const DECODE_PTS: Record<number, 'ulaw' | 'alaw'> = { 0: 'ulaw', 8: 'alaw' };
const SAMPLE_RATE = 8000;
const ACTIVE_RMS = 500;          // 与静音分析一致的"有人声"门限

const FRAME = 256;               // 帧长 32ms @8kHz
const HOP = 128;                 // 帧移 16ms
const TONE_BAND_LO = 250.0;      // 啸叫检测频带下限（8k 采样奈奎斯特 4kHz）
const TONE_BAND_HI = 3900.0;     // 啸叫检测频带上限
const TONE_PROMINENCE = 40.0;    // 谱峰 / 谱中位数 ≥40 倍才够"窄而尖"
const TONE_MIN_RMS = 300;        // 帧能量下限（排除底噪里的伪峰）
const TONE_MIN_FRAMES = 10;      // 持续 ≥10 帧（约 0.16s）判为持续单频音
const TONE_FREQ_TOL_HZ = 50.0;   // 同一事件内允许的频率漂移
const PROMPT_FREQS = [425.0, 440.0, 450.0, 480.0]; // 常见呼叫提示音频率
const PROMPT_FREQ_TOL_HZ = 40.0; // 匹配容差（FFT bin 宽 31.25Hz）
const PROMPT_MAX_S = 6.0;        // 短于此的提示音频单音归为提示音
const HUM_LOW_HZ = 220.0;        // 低频嗡声的"低频段"上界
const HUM_RATIO = 0.85;          // 低频能量占比门限
const HUM_MIN_RMS = 800;         // 嗡声要有可闻电平
const HUM_MIN_FRAMES = 50;       // 持续 ≥0.8s
const CLIP_MIN_LEVEL = 20000;    // 削波采样幅度下限
const CLIP_MIN_RUN = 4;          // 连续 ≥4 个相等大幅值采样才算削平
const CLIP_MIN_RUNS = 2;         // 至少出现 2 次平台才报
const SPIKE_LEVEL = 24000;       // 爆点尖峰幅度
const SPIKE_NEIGHBOR = 4000;     // 尖峰前后邻域必须都低于此值
const NOISE_FLOOR_DBFS = -45.0;  // 底噪门限
const SPEECH_LOW_DBFS = -27.0;   // 话音平均电平过低门限
const SPEECH_HIGH_DBFS = -9.0;   // 话音平均电平过高门限
const MAX_EVENTS = 40;           // 每类事件明细最多保留条数

const SPEECH_CV = 0.5;           // 人声包络起伏下限（变异系数）
const SPEECH_SPREAD = 0.55;      // 包络 p10/p50 下展门限
const VOICE_ABOVE_FLOOR = 1.8;   // 高于背景电平 1.8×（≈+5dB）的突发按人声计
const VOICE_MIN_EPISODE = 10;    // 突发至少持续 10 个统计样本

// ---------- RFC 6184 NAL 类型 ----------
const NAL_IDR = 5, NAL_SPS = 7, NAL_PPS = 8;
const NAL_STAP_A = 24, NAL_FU_A = 28;

// ---------- 结果类型 ----------
export type QualitySeverity = 'critical' | 'warning' | 'info';

export interface QualityIssue {
  kind: string;
  severity: QualitySeverity;
  message: string;
}

export interface RtpIntegrityResult {
  seqContinuous: boolean;
  seqGaps: number;
  lostPackets: number;
  lossRatePct: number;
  monotonic: boolean;
  tsBackward: number;
  tsDuplicate: number;
  tsWrap: number;
  medianTsDelta: number;
  packetDurationMs: number | null;
  zeroFilledMs: number;
  otherPtPackets: number;
}

export type ToneBand = 'howl' | 'prompt' | 'hum';

export interface ToneEvent {
  startS: number;
  endS: number;
  freqHz: number | null;
  band: ToneBand;
  meanDbfs: number;
}

export interface TonesSummary {
  count: number;
  howlCount: number;
  promptCount: number;
  humCount: number;
  events: ToneEvent[];
}

export interface ClipEvent {
  timeS: number;
  ms: number;
  levelDbfs: number;
}

export interface ClickEvent {
  timeS: number;
  amplitudeDbfs: number;
}

export interface AudioQualityResult {
  packetCount: number;
  codec: string;
  decodable: boolean;
  durationS: number;
  rtpIntegrity: RtpIntegrityResult | null;
  clipping: { runCount: number; sampleCount: number; events: ClipEvent[] };
  clicks: { count: number; events: ClickEvent[] };
  tones: TonesSummary;
  noiseFloorDbfs: number | null;
  speechLevelDbfs: number | null;
  speechActivity: boolean | null;
  steadyLevelDbfs: number | null;
  issues: QualityIssue[];
  verdict: 'clean' | 'noisy' | 'bad' | 'silent' | 'unknown';
}

export interface VideoLossEvent {
  timeS: number;
  count: number;
}

export interface VideoQualityResult {
  packetCount: number;
  totalLost: number;
  lossRatePct: number;
  maxConsecutiveLoss: number;
  lossEvents: VideoLossEvent[];
  nalUnits: number;
  idrCount: number;
  spsCount: number;
  ppsCount: number;
  brokenNals: number;
  idrIntervalMaxS: number | null;
  firstIdrS: number | null;
  estArtifactsMs: number;
  /** 桌面端无 ffmpeg：恒为 'skipped' */
  decodeCheck: 'ok' | 'errors' | 'skipped' | 'unavailable';
  decodeErrors: number | null;
  /** 桌面端无 ffmpeg 解码校验的说明 */
  ffmpegNote: string;
  rtpIntegrity: RtpIntegrityResult | null;
  durationS?: number;
  issues: QualityIssue[];
  verdict: 'ok' | 'risk' | 'bad' | 'unknown';
}

// ---------- 基础工具 ----------
function roundN(v: number, d: number): number {
  const m = Math.pow(10, d);
  return Math.round(v * m) / m;
}

/** numpy 风格四舍六入五取整（round-half-even），用于谱 bin 取整 */
function npRound(v: number): number {
  const fl = Math.floor(v);
  const diff = v - fl;
  if (diff > 0.5) return fl + 1;
  if (diff < 0.5) return fl;
  return fl % 2 === 0 ? fl : fl + 1;
}

function meanOf(values: ArrayLike<number>): number {
  let s = 0;
  for (let i = 0; i < values.length; i++) s += values[i];
  return values.length ? s / values.length : 0;
}

function medianOf(values: ArrayLike<number>): number {
  if (!values.length) return 0;
  const a = Array.from(values).sort((x, y) => x - y);
  const mid = a.length >> 1;
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

/** numpy 默认（linear 插值）百分位 */
function percentileOf(values: ArrayLike<number>, p: number): number {
  if (!values.length) return 0;
  const a = Array.from(values).sort((x, y) => x - y);
  const idx = (p / 100) * (a.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  return a[lo] + (a[hi] - a[lo]) * (idx - lo);
}

/** 布尔数组的连续 True 段 [(start, length)] */
function boolRuns(mask: ArrayLike<number>): { start: number; length: number }[] {
  const n = mask.length;
  const runs: { start: number; length: number }[] = [];
  let s = -1;
  for (let i = 0; i < n; i++) {
    if (mask[i]) {
      if (s < 0) s = i;
    } else if (s >= 0) {
      runs.push({ start: s, length: i - s });
      s = -1;
    }
  }
  if (s >= 0) runs.push({ start: s, length: n - s });
  return runs;
}

function dbfs(rms: number): number {
  return roundN(20 * Math.log10(Math.max(rms, 1) / 32768), 1);
}

// ---------- radix-2 FFT（本文件自实现） ----------
const twiddleCache = new Map<number, { cos: Float64Array; sin: Float64Array }>();

function getTwiddles(n: number): { cos: Float64Array; sin: Float64Array } {
  let t = twiddleCache.get(n);
  if (!t) {
    const cos = new Float64Array(n >> 1);
    const sin = new Float64Array(n >> 1);
    for (let k = 0; k < (n >> 1); k++) {
      const ang = (-2 * Math.PI * k) / n;
      cos[k] = Math.cos(ang);
      sin[k] = Math.sin(ang);
    }
    t = { cos, sin };
    twiddleCache.set(n, t);
  }
  return t;
}

/** 就地基-2 FFT（长度须为 2 的幂） */
function fftInPlace(re: Float64Array, im: Float64Array): void {
  const n = re.length;
  const tw = getTwiddles(n);
  // 位反转置换
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tr = re[i]; re[i] = re[j]; re[j] = tr;
      const ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const half = len >> 1;
    const step = n / len;
    for (let i = 0; i < n; i += len) {
      for (let k = 0; k < half; k++) {
        const wr = tw.cos[k * step];
        const wi = tw.sin[k * step];
        const xr = re[i + k + half];
        const xi = im[i + k + half];
        const vr = xr * wr - xi * wi;
        const vi = xr * wi + xi * wr;
        const ur = re[i + k];
        const ui = im[i + k];
        re[i + k] = ur + vr;
        im[i + k] = ui + vi;
        re[i + k + half] = ur - vr;
        im[i + k + half] = ui - vi;
      }
    }
  }
}

// ---------- G.711 解码（与 audioop ulaw2lin/alaw2lin 一致，宽度 2 字节） ----------
function ulaw2linear(u: number): number {
  u = ~u & 0xff;
  let t = ((u & 0x0f) << 3) + 0x84;
  t <<= (u & 0x70) >> 4;
  return u & 0x80 ? 0x84 - t : t - 0x84;
}

function alaw2linear(a: number): number {
  a ^= 0x55;
  let t = (a & 0x0f) << 4;
  const seg = (a & 0x70) >> 4;
  switch (seg) {
    case 0:
      t += 8;
      break;
    case 1:
      t += 0x108;
      break;
    default:
      t += 0x108;
      t <<= seg - 1;
  }
  return a & 0x80 ? t : -t;
}

// ---------- RTP 序号/时间戳秩序 ----------
export function rtpIntegrityCheck(
  items: { seq: number; ts: number; pt: number }[],
  spp: number,
  mainPt: number,
  mode: 'packet' | 'frame' = 'packet',
): RtpIntegrityResult {
  let seqGaps = 0;
  let lost = 0;
  for (let i = 1; i < items.length; i++) {
    const dSeq = (items[i].seq - items[i - 1].seq) & 0xffff;
    if (dSeq > 1) {
      seqGaps += 1;
      lost += dSeq - 1;
    }
  }
  let tsBackward = 0, tsDuplicate = 0, tsWrap = 0, otherPt = 0;
  let prevTs: number | null = null;
  for (const it of items) {
    if (it.pt !== mainPt) {
      otherPt += 1;
      continue;
    }
    if (prevTs !== null) {
      const dTs = signed32(it.ts - prevTs);
      if (dTs < 0) {
        tsBackward += 1;
      } else if (dTs === 0) {
        if (mode === 'packet') tsDuplicate += 1;
      } else if (it.ts < prevTs) {
        tsWrap += 1;
      }
    }
    prevTs = it.ts;
  }
  return {
    seqContinuous: lost === 0,
    seqGaps,
    lostPackets: lost,
    lossRatePct: lost ? roundN((lost / (items.length + lost)) * 100, 2) : 0.0,
    monotonic: tsBackward === 0,
    tsBackward,
    tsDuplicate,
    tsWrap,
    medianTsDelta: spp,
    packetDurationMs: spp ? roundN((spp / SAMPLE_RATE) * 1000, 2) : null,
    zeroFilledMs: 0.0,
    otherPtPackets: otherPt,
  };
}

// ---------- 单频/嗡声事件追踪 ----------
/** 把布尔帧串成持续事件（[(start_t, end_t)]），1 帧空洞自动桥接 */
function trackRuns(
  isFlag: Uint8Array,
  frameT: Float64Array,
  minFrames: number,
): [number, number][] {
  const n = isFlag.length;
  const filled = new Uint8Array(isFlag);
  for (let i = 1; i < n - 1; i++) {
    if (isFlag[i - 1] && isFlag[i + 1]) filled[i] = 1;
  }
  const events: [number, number][] = [];
  for (const { start, length } of boolRuns(filled)) {
    if (length >= minFrames) {
      events.push([frameT[start], frameT[start + length - 1]]);
    }
  }
  const merged: [number, number][] = [];
  for (const [s, e] of events) {
    if (merged.length && s - merged[merged.length - 1][1] <= (HOP / SAMPLE_RATE) * 4) {
      merged[merged.length - 1][1] = e;
    } else {
      merged.push([s, e]);
    }
  }
  return merged;
}

function isPromptFreq(f: number): boolean {
  return PROMPT_FREQS.some((pf) => Math.abs(f - pf) <= PROMPT_FREQ_TOL_HZ);
}

/** 谱峰的 2f/3f/f÷2 处也有显著峰 → 是语音谐波结构，不是纯单频。df: bin 宽 Hz */
function harmonicMask(
  spec: Float64Array,
  nFrames: number,
  nBins: number,
  df: number,
  peakFreq: Float64Array,
  peakVal: Float64Array,
): Uint8Array {
  const harm = new Uint8Array(nFrames);
  for (const mult of [2.0, 3.0, 0.5]) {
    const tgt = new Int32Array(nFrames);
    const idxs: number[] = [];
    for (let f = 0; f < nFrames; f++) {
      const t = npRound((peakFreq[f] * mult) / df);
      tgt[f] = t;
      if (t >= 1 && t < nBins) idxs.push(f);
    }
    if (!idxs.length) continue;
    for (const f of idxs) {
      const b = tgt[f];
      let mag = spec[f * nBins + b];
      mag = Math.max(mag, spec[f * nBins + Math.max(b - 1, 0)]);
      mag = Math.max(mag, spec[f * nBins + Math.min(b + 1, nBins - 1)]);
      if (mag > 0.25 * peakVal[f]) harm[f] = 1;
    }
  }
  return harm;
}

/** 直流主导的帧（恒定电平信号）不是振荡，不能按单频音/嗡声判定 */
function dcDominant(spec: Float64Array, nFrames: number, nBins: number): Uint8Array {
  const out = new Uint8Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    let rest = 0;
    for (let b = 1; b < nBins; b++) rest += spec[f * nBins + b];
    if (spec[f * nBins] > rest) out[f] = 1;
  }
  return out;
}

/** 活跃样本中哪些属于人声（其余为平稳背景电平）。返回 null=样本太少 */
function voiceMask(rmsSeq: number[]): boolean[] | null {
  const n = rmsSeq.length;
  if (n < 25) return null;
  // np.convolve(ones(5)/5, mode='same')：±2 采样滑窗、边界补零
  const env = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    let s = 0;
    for (let j = i - 2; j <= i + 2; j++) {
      if (j >= 0 && j < n) s += rmsSeq[j];
    }
    env[i] = s / 5;
  }
  const mean = meanOf(env);
  let varr = 0;
  for (let i = 0; i < n; i++) varr += (env[i] - mean) * (env[i] - mean);
  varr /= n;
  const cv = Math.sqrt(varr) / Math.max(mean, 1e-9);
  const p50 = Math.max(percentileOf(env, 50), 1e-9);
  const spread = percentileOf(env, 10) / p50;
  if (cv >= SPEECH_CV || spread <= SPEECH_SPREAD) {
    return new Array<boolean>(n).fill(true);
  }
  const mask: boolean[] = [];
  for (let i = 0; i < n; i++) mask.push(env[i] >= p50 * VOICE_ABOVE_FLOOR);
  for (const { start, length } of boolRuns(mask.map((v) => (v ? 1 : 0)))) {
    if (length < VOICE_MIN_EPISODE) {
      for (let i = start; i < start + length; i++) mask[i] = false;
    }
  }
  return mask;
}

/** 把"单频帧"串成持续事件：先填 1 帧空洞，再按频率漂移分段并归类 band */
function trackTones(
  isTone: Uint8Array,
  peakFreq: Float64Array,
  frameRms: Float64Array,
  frameT: Float64Array,
): TonesSummary {
  const n = isTone.length;
  const filled = new Uint8Array(isTone);
  for (let i = 1; i < n - 1; i++) {
    if (isTone[i - 1] && isTone[i + 1]) filled[i] = 1;
  }
  const frameGroups: number[][] = [];
  for (const { start, length } of boolRuns(filled)) {
    if (length < TONE_MIN_FRAMES) continue;
    let seg = [start];
    for (let i = start + 1; i < start + length; i++) {
      if (Math.abs(peakFreq[i] - peakFreq[seg[0]]) > TONE_FREQ_TOL_HZ) {
        if (seg.length >= TONE_MIN_FRAMES) frameGroups.push(seg);
        seg = [i];
      } else {
        seg.push(i);
      }
    }
    if (seg.length >= TONE_MIN_FRAMES) frameGroups.push(seg);
  }

  const out: ToneEvent[] = [];
  for (const idx of frameGroups) {
    const fMean = medianOf(idx.map((i) => peakFreq[i]));
    const level = dbfs(meanOf(idx.map((i) => frameRms[i])));
    const dur = frameT[idx[idx.length - 1]] - frameT[idx[0]];
    const band: ToneBand =
      fMean >= TONE_BAND_LO
        ? isPromptFreq(fMean) && dur <= PROMPT_MAX_S ? 'prompt' : 'howl'
        : 'hum';
    out.push({
      startS: roundN(frameT[idx[0]], 2),
      endS: roundN(frameT[idx[idx.length - 1]], 2),
      freqHz: roundN(fMean, 1),
      band,
      meanDbfs: level,
    });
  }
  return {
    count: out.length,
    howlCount: out.filter((e) => e.band === 'howl').length,
    promptCount: out.filter((e) => e.band === 'prompt').length,
    humCount: 0,
    events: out.slice(0, MAX_EVENTS),
  };
}

/** 音频主分析：按 seq（播放）顺序拼接 PCM（DTX 补零），做帧级 DSP 检测 */
export function analyzeAudioQuality(packets: PacketMap, ssrc: number): AudioQualityResult {
  const result: AudioQualityResult = {
    packetCount: 0,
    codec: 'unknown',
    decodable: false,
    durationS: 0.0,
    rtpIntegrity: null,
    clipping: { runCount: 0, sampleCount: 0, events: [] },
    clicks: { count: 0, events: [] },
    tones: { count: 0, howlCount: 0, promptCount: 0, humCount: 0, events: [] },
    noiseFloorDbfs: null,
    speechLevelDbfs: null,
    speechActivity: null,
    steadyLevelDbfs: null,
    issues: [],
    verdict: 'clean',
  };

  const bySeq = packets.get(ssrc);
  if (!bySeq || bySeq.size === 0) return result;
  const stream = bySeq; // (ssrc, seq) 已在提取时去重，Python 侧 len(v)>=8 恒满足

  const ptCount = new Map<number, number>();
  for (const v of stream.values()) ptCount.set(v.pt, (ptCount.get(v.pt) ?? 0) + 1);
  let pt = 0;
  let ptBest = -1;
  for (const [p, c] of ptCount) {
    if (c > ptBest) {
      ptBest = c;
      pt = p;
    }
  }
  result.packetCount = stream.size;
  result.codec = getPtName(pt);
  result.decodable = pt in DECODE_PTS;
  if (!result.decodable) {
    // 其他编码诚实标注不可解
    result.verdict = 'unknown';
    return result;
  }

  const seqs = [...stream.keys()].sort((a, b) => a - b);
  const deltas: number[] = [];
  for (let i = 1; i < seqs.length; i++) {
    deltas.push(signed32(stream.get(seqs[i])!.rtpTs - stream.get(seqs[i - 1])!.rtpTs));
  }
  const positive = deltas.filter((d) => d > 0).sort((a, b) => a - b);
  let spp = positive.length ? positive[Math.floor(positive.length / 2)] : 0;
  if (!(spp > 0 && spp <= SAMPLE_RATE / 2)) spp = 160;
  const integrity = rtpIntegrityCheck(
    seqs.map((s) => ({ seq: s, ts: stream.get(s)!.rtpTs, pt: stream.get(s)!.pt })),
    spp,
    pt,
    'packet',
  );
  result.rtpIntegrity = integrity;

  // 拼接 PCM（含 DTX 补零），媒体时间 = 采样位置 / 采样率
  const chunks: Float64Array[] = [];
  let zeroFilled = 0;
  let prevTs: number | null = null;
  const decodeFn = DECODE_PTS[pt] === 'ulaw' ? ulaw2linear : alaw2linear;
  for (const seq of seqs) {
    const rec = stream.get(seq)!;
    const ts = rec.rtpTs;
    if (prevTs !== null) {
      const gap = signed32(ts - prevTs) - spp;
      if (gap > 0 && gap <= 10 * SAMPLE_RATE) {
        chunks.push(new Float64Array(gap)); // DTX/静音抑制缺口补零
        zeroFilled += gap;
      }
    }
    const payload = rec.payload;
    if (rec.pt === pt) {
      const lin = new Float64Array(payload ? payload.length : 0);
      for (let i = 0; i < lin.length; i++) lin[i] = decodeFn(payload![i]);
      chunks.push(lin);
    } else {
      chunks.push(new Float64Array(spp)); // 非主 PT 包（如 CN）按一包静音处理
    }
    prevTs = ts;
  }
  let totalLen = 0;
  for (const c of chunks) totalLen += c.length;
  const x = new Float64Array(totalLen);
  let off0 = 0;
  for (const c of chunks) {
    x.set(c, off0);
    off0 += c.length;
  }
  result.durationS = roundN(x.length / SAMPLE_RATE, 2);
  integrity.zeroFilledMs = roundN((zeroFilled / SAMPLE_RATE) * 1000, 1);
  if (x.length < FRAME) return result;

  // —— 帧级分析：RMS / 频谱 ——
  const nFrames = Math.floor((x.length - FRAME) / HOP) + 1;
  const nBins = FRAME / 2 + 1; // 129（rfft）
  const spec = new Float64Array(nFrames * nBins);
  const win = new Float64Array(FRAME);
  for (let i = 0; i < FRAME; i++) {
    win[i] = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (FRAME - 1)); // 汉宁窗
  }
  const re = new Float64Array(FRAME);
  const im = new Float64Array(FRAME);
  const frameRms = new Float64Array(nFrames);
  const frameT = new Float64Array(nFrames); // 帧中心媒体时间
  for (let f = 0; f < nFrames; f++) {
    const off = f * HOP;
    let sum2 = 0;
    for (let i = 0; i < FRAME; i++) {
      const raw = x[off + i];
      sum2 += raw * raw;
      re[i] = raw * win[i];
      im[i] = 0;
    }
    fftInPlace(re, im);
    for (let b = 0; b < nBins; b++) {
      spec[f * nBins + b] = Math.hypot(re[b], im[b]);
    }
    frameRms[f] = Math.sqrt(sum2 / FRAME);
    frameT[f] = (off + FRAME / 2) / SAMPLE_RATE;
  }
  const df = SAMPLE_RATE / FRAME; // 频谱 bin 宽 31.25Hz
  const freqAt = (b: number) => (b * SAMPLE_RATE) / FRAME;

  // 1) 啸叫 / 持续单频音：谱峰显著、持续、频率稳定，且无谐波伙伴
  const bandIdx: number[] = [];
  for (let b = 0; b < nBins; b++) {
    if (freqAt(b) >= TONE_BAND_LO && freqAt(b) <= TONE_BAND_HI) bandIdx.push(b);
  }
  const peakVal = new Float64Array(nFrames);
  const peakFreq = new Float64Array(nFrames);
  const med = new Float64Array(nFrames);
  const globalPeak = new Float64Array(nFrames);
  const scratch = new Array<number>(nBins - 1);
  for (let f = 0; f < nFrames; f++) {
    let bestB = bandIdx[0];
    let bestV = -1;
    for (const b of bandIdx) {
      const v = spec[f * nBins + b];
      if (v > bestV) {
        bestV = v;
        bestB = b;
      }
    }
    peakVal[f] = bestV;
    peakFreq[f] = freqAt(bestB);
    let gp = -1;
    let restSum = 0;
    for (let b = 1; b < nBins; b++) {
      const v = spec[f * nBins + b];
      scratch[b - 1] = v;
      restSum += v;
      if (v > gp) gp = v;
    }
    globalPeak[f] = gp;
    med[f] = Math.max(medianOf(scratch), 1e-6);
  }
  const dcDom = dcDominant(spec, nFrames, nBins);
  const harm = harmonicMask(spec, nFrames, nBins, df, peakFreq, peakVal);
  const isTone = new Uint8Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    // 带内峰必须是全谱最大分量：低于频段下限的单频主瓣泄进带内要排除
    if (
      peakVal[f] / med[f] >= TONE_PROMINENCE &&
      peakVal[f] >= globalPeak[f] &&
      frameRms[f] >= TONE_MIN_RMS &&
      !harm[f] &&
      !dcDom[f]
    ) {
      isTone[f] = 1;
    }
  }
  result.tones = trackTones(isTone, peakFreq, frameRms, frameT);

  // 提示音/单频音覆盖的帧：削波与话音电平统计要剔除（边缘外扩一整帧）
  const toneFrame = new Uint8Array(nFrames);
  const edge = FRAME / SAMPLE_RATE;
  for (const ev of result.tones.events) {
    if (ev.band === 'hum') continue;
    for (let f = 0; f < nFrames; f++) {
      if (frameT[f] >= ev.startS - edge && frameT[f] <= ev.endS + edge) toneFrame[f] = 1;
    }
  }

  // 2) 低频嗡声：低频能量占比高的持续帧（与啸叫独立判定）
  const lowBins: number[] = [];
  for (let b = 0; b < nBins; b++) {
    if (freqAt(b) <= HUM_LOW_HZ && b !== 0) lowBins.push(b); // 排除直流
  }
  const isHum = new Uint8Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    let lowEnergy = 0;
    let totalEnergy = 0;
    for (const b of lowBins) lowEnergy += spec[f * nBins + b] ** 2;
    for (let b = 1; b < nBins; b++) totalEnergy += spec[f * nBins + b] ** 2;
    const lowRatio = lowEnergy / Math.max(totalEnergy, 1e-9);
    if (lowRatio >= HUM_RATIO && frameRms[f] >= HUM_MIN_RMS && !dcDom[f]) isHum[f] = 1;
  }
  const hum = trackRuns(isHum, frameT, HUM_MIN_FRAMES);
  result.tones.humCount = hum.length;
  result.tones.count += hum.length;
  for (const [start, end] of hum.slice(0, MAX_EVENTS)) {
    const sel: number[] = [];
    for (let f = 0; f < nFrames; f++) {
      if (frameT[f] >= start && frameT[f] <= end) sel.push(frameRms[f]);
    }
    result.tones.events.push({
      startS: roundN(start, 2),
      endS: roundN(end, 2),
      freqHz: null,
      band: 'hum',
      meanDbfs: dbfs(meanOf(sel)),
    });
  }

  // 3) 削波：连续相等的大幅值采样（波形被削平的平台）。
  //    落在提示音/单频音事件内的削顶不报；嗡声段里的削顶照常报
  const toneSamp = new Uint8Array(x.length);
  for (const ev of result.tones.events) {
    if (ev.band === 'hum') continue;
    const i0 = Math.max(Math.trunc(ev.startS * SAMPLE_RATE) - FRAME, 0);
    const i1 = Math.min(Math.trunc(ev.endS * SAMPLE_RATE) + FRAME, x.length);
    for (let i = i0; i < i1; i++) toneSamp[i] = 1;
  }
  const diffMask = new Uint8Array(Math.max(x.length - 1, 0));
  for (let i = 0; i < diffMask.length; i++) diffMask[i] = x[i] === x[i + 1] ? 1 : 0;
  const clipEvents: { start: number; length: number; level: number }[] = [];
  for (const { start, length } of boolRuns(diffMask)) {
    if (length + 1 < CLIP_MIN_RUN) continue;
    const level = Math.abs(x[start]);
    if (level < CLIP_MIN_LEVEL || toneSamp[start]) continue;
    clipEvents.push({ start, length: length + 1, level });
  }
  result.clipping.runCount = clipEvents.length;
  result.clipping.sampleCount = clipEvents.reduce((n, c) => n + c.length, 0);
  for (const c of clipEvents.slice(0, MAX_EVENTS)) {
    result.clipping.events.push({
      timeS: roundN(c.start / SAMPLE_RATE, 2),
      ms: roundN((c.length / SAMPLE_RATE) * 1000, 2),
      levelDbfs: dbfs(c.level),
    });
  }

  // 4) 爆点：孤立脉冲短突发（幅度极大、突发外围 ±4 采样都很小）
  const big = new Uint8Array(x.length);
  const small = new Uint8Array(x.length);
  for (let i = 0; i < x.length; i++) {
    big[i] = Math.abs(x[i]) >= SPIKE_LEVEL ? 1 : 0;
    small[i] = Math.abs(x[i]) < SPIKE_NEIGHBOR ? 1 : 0;
  }
  const bursts: [number, number][] = [];
  for (const { start: s, length } of boolRuns(big)) {
    if (bursts.length && s - bursts[bursts.length - 1][1] <= 4) {
      bursts[bursts.length - 1][1] = s + length; // 相邻尖峰合并为同一爆点
    } else {
      bursts.push([s, s + length]);
    }
  }
  const merged: [number, number][] = [];
  for (const [s, e] of bursts) {
    if (e - s > 6) continue; // 长突发不是"孤立爆点"
    let ok = true;
    for (let i = Math.max(s - 4, 0); i < s; i++) if (!small[i]) { ok = false; break; }
    if (!ok) continue;
    for (let i = e; i < Math.min(e + 4, x.length); i++) if (!small[i]) { ok = false; break; }
    if (!ok) continue;
    merged.push([s, e]);
  }
  result.clicks.count = merged.length;
  for (const [s, e] of merged.slice(0, MAX_EVENTS)) {
    let amp = 1;
    for (let i = s; i < e; i++) amp = Math.max(amp, Math.abs(x[i]));
    result.clicks.events.push({
      timeS: roundN(s / SAMPLE_RATE, 2),
      amplitudeDbfs: dbfs(amp),
    });
  }

  // 5) 底噪与话音电平：话音统计剔除提示音帧
  const quiet: number[] = [];
  const speech: number[] = [];
  for (let f = 0; f < nFrames; f++) {
    if (frameRms[f] < ACTIVE_RMS) quiet.push(frameRms[f]);
    else if (!toneFrame[f]) speech.push(frameRms[f]);
  }
  if (quiet.length >= 10) {
    result.noiseFloorDbfs = dbfs(medianOf(quiet));
  }
  const vmask = voiceMask(speech);
  if (vmask === null) {
    result.speechActivity = null;
  } else if (vmask.some((v) => v)) {
    result.speechActivity = true;
    const voiced: number[] = [];
    const other: number[] = [];
    for (let i = 0; i < speech.length; i++) (vmask[i] ? voiced : other).push(speech[i]);
    result.speechLevelDbfs = dbfs(meanOf(voiced));
    if (other.length >= 10) {
      result.steadyLevelDbfs = dbfs(meanOf(other));
    }
  } else {
    result.speechActivity = false;
    result.steadyLevelDbfs = dbfs(meanOf(speech));
  }

  result.issues = audioIssues(result);
  const worst = new Set(result.issues.map((i) => i.severity));
  const kinds = new Set(result.issues.map((i) => i.kind));
  if (worst.has('critical')) result.verdict = 'bad';
  else if (kinds.has('no_speech')) result.verdict = 'silent'; // 除提示音外全程无声
  else if (worst.has('warning')) result.verdict = 'noisy';
  else result.verdict = 'clean';
  return result;
}

/** 把检测结果翻译成面向用户的结论（不含流名，由报告层加前缀） */
function audioIssues(r: AudioQualityResult): QualityIssue[] {
  const issues: QualityIssue[] = [];
  const integ = r.rtpIntegrity;
  if (integ?.tsBackward) {
    issues.push({
      kind: 'rtp_order',
      severity: 'critical',
      message:
        `RTP 时间戳倒退 ${integ.tsBackward} 处（按序号排列后媒体时钟往回走）——发送端时钟异常，` +
        `按序号拼接的音频会错位，可能产生卡顿杂音，本流杂音类检测结论的可信度也下降`,
    });
  }
  if (integ?.tsDuplicate) {
    issues.push({
      kind: 'rtp_order',
      severity: 'warning',
      message:
        `RTP 时间戳重复 ${integ.tsDuplicate} 处（序号前进但媒体时间原地踏步）——发送端时钟停走或冗余重传，听感为重复音/卡顿`,
    });
  }
  if (integ && integ.lostPackets) {
    issues.push({
      kind: 'rtp_loss',
      severity: integ.lossRatePct >= 3 ? 'critical' : 'warning',
      message:
        `RTP 序号不连续：缺口 ${integ.seqGaps} 处、丢 ${integ.lostPackets} 包` +
        `（${integ.lossRatePct.toFixed(2)}%）——缺失音频已按静音补零 ` +
        `${integ.zeroFilledMs || 0} ms，丢包处听感为断音/吞字，底噪与电平统计含补零段`,
    });
  } else if (integ && integ.monotonic && !integ.tsDuplicate) {
    const extra = integ.zeroFilledMs ? `（静音抑制补零 ${integ.zeroFilledMs} ms）` : '';
    const other = integ.otherPtPackets
      ? `（另有 ${integ.otherPtPackets} 个其他载荷类型包（如 DTMF 电话事件），不参与秩序判定）`
      : '';
    issues.push({
      kind: 'rtp_ok',
      severity: 'info',
      message:
        `RTP 序号连续正向（每包 +1）、时间戳单调递增（每包 +${integ.medianTsDelta} ≈ ` +
        `${integ.packetDurationMs === null ? 'None' : integ.packetDurationMs} ms）${extra}${other}` +
        `——重建音频与杂音/啸叫检测的基础数据可信`,
    });
  }
  const tones = r.tones;
  if (tones.promptCount) {
    const ev = tones.events.filter((e) => e.band === 'prompt');
    const longest = Math.max(...ev.map((e) => e.endS - e.startS));
    const freqs = ev
      .slice(0, 3)
      .map((e) => `${e.freqHz === null ? 0 : Math.round(e.freqHz)}Hz`)
      .join('、');
    issues.push({
      kind: 'prompt_tone',
      severity: 'info',
      message:
        `检测到呼叫提示音 ${tones.promptCount} 处（${freqs}，最长 ${longest.toFixed(1)} 秒，` +
        `电平约 ${ev[0].meanDbfs} dBFS）——回铃音/忙音类单频流程音，属正常呼叫信号，不是啸叫`,
    });
  }
  if (tones.howlCount) {
    const ev = tones.events.filter((e) => e.band === 'howl');
    const longest = Math.max(...ev.map((e) => e.endS - e.startS));
    const freqs = ev
      .slice(0, 3)
      .map((e) => `${e.freqHz === null ? 0 : Math.round(e.freqHz)}Hz`)
      .join('、');
    issues.push({
      kind: 'howling',
      severity: 'critical',
      message:
        `检测到啸叫/持续单频音 ${tones.howlCount} 处（${freqs}，最长 ${longest.toFixed(1)} 秒，` +
        `电平约 ${ev[0].meanDbfs} dBFS）——通话中的尖啸/嘀声，通常为扬声器回授啸叫或单音提示音串入通话`,
    });
  }
  if (tones.humCount) {
    issues.push({
      kind: 'hum',
      severity: 'warning',
      message:
        `检测到低频嗡声 ${tones.humCount} 处（能量集中在低频段持续存在，典型为 50/100Hz 电源干扰、` +
        `接地环路或设备风扇声串入采集）`,
    });
  }
  const clip = r.clipping;
  if (clip.runCount >= CLIP_MIN_RUNS) {
    issues.push({
      kind: 'clipping',
      severity: clip.sampleCount > 200 ? 'critical' : 'warning',
      message:
        `检测到波形削波 ${clip.runCount} 处（共 ${clip.sampleCount} 个采样被削平）——发话端音量` +
        `过大导致破音，听感为沙哑、噼啪的杂音`,
    });
  }
  const clicks = r.clicks;
  if (clicks.count >= 3) {
    issues.push({
      kind: 'clicks',
      severity: 'warning',
      message:
        `检测到 ${clicks.count} 个爆点/咔哒声（孤立脉冲尖峰）——多为突发电气干扰、设备切换或线路接触不良`,
    });
  }
  const nf = r.noiseFloorDbfs;
  if (nf !== null && nf > NOISE_FLOOR_DBFS) {
    issues.push({
      kind: 'noise',
      severity: nf > -40 ? 'warning' : 'info',
      message:
        `静音段底噪约 ${nf} dBFS，偏高——对方环境噪声或拾音设备底噪会一直传过来，听感为持续的沙沙/电流声`,
    });
  }
  if (r.durationS >= 10 && r.speechLevelDbfs === null) {
    // 剔除提示音/单频音后没有任何有人声的帧：该方向全程没有有效人声内容
    const steady = r.steadyLevelDbfs;
    let detail: string;
    if (steady !== null) {
      detail = `有持续背景电平（约 ${steady} dBFS，疑似供电干扰/环境噪声），但没有说话的音节起伏`;
    } else {
      detail = `除提示音/单频音外基本为静音，底噪约 ${nf === null ? '—' : nf} dBFS`;
    }
    issues.push({
      kind: 'no_speech',
      severity: 'warning',
      message:
        `媒体时长 ${Math.round(r.durationS)} 秒，全程未检测到话音（${detail}）——发声端没有把` +
        `有效人声内容送出来，听感为只有提示音/持续噪声/完全无声`,
    });
  }
  const sl = r.speechLevelDbfs;
  if (sl !== null && sl < SPEECH_LOW_DBFS) {
    issues.push({
      kind: 'low_level',
      severity: 'info',
      message: `话音平均电平仅 ${sl} dBFS，偏低——对方会感觉声音小、发虚（不是杂音，但常与听不清的投诉相关）`,
    });
  } else if (sl !== null && sl > SPEECH_HIGH_DBFS) {
    issues.push({
      kind: 'high_level',
      severity: 'info',
      message: `话音平均电平 ${sl} dBFS，接近满幅——再大就会削波破音，建议调低发送增益`,
    });
  }
  return issues;
}

/** 检测 PCM 中的稳态单频段（提示音/啸叫/低频嗡声），返回 [(start_s, end_s)]。
 *  帧级判定与 analyzeAudioQuality 同一套参数，供静音分析把提示音从
 *  "有人声"时间里剔除——回铃音不是人声。 */
export function toneIntervals(x: Float64Array): [number, number][] {
  if (x.length < FRAME) return [];
  const nFrames = Math.floor((x.length - FRAME) / HOP) + 1;
  const nBins = FRAME / 2 + 1;
  const spec = new Float64Array(nFrames * nBins);
  const win = new Float64Array(FRAME);
  for (let i = 0; i < FRAME; i++) {
    win[i] = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (FRAME - 1));
  }
  const re = new Float64Array(FRAME);
  const im = new Float64Array(FRAME);
  const frameRms = new Float64Array(nFrames);
  const frameT = new Float64Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    const off = f * HOP;
    let sum2 = 0;
    for (let i = 0; i < FRAME; i++) {
      const raw = x[off + i];
      sum2 += raw * raw;
      re[i] = raw * win[i];
      im[i] = 0;
    }
    fftInPlace(re, im);
    for (let b = 0; b < nBins; b++) spec[f * nBins + b] = Math.hypot(re[b], im[b]);
    frameRms[f] = Math.sqrt(sum2 / FRAME);
    frameT[f] = (off + FRAME / 2) / SAMPLE_RATE;
  }
  const df = SAMPLE_RATE / FRAME;
  const freqAt = (b: number) => (b * SAMPLE_RATE) / FRAME;

  const bandIdx: number[] = [];
  for (let b = 0; b < nBins; b++) {
    if (freqAt(b) >= TONE_BAND_LO && freqAt(b) <= TONE_BAND_HI) bandIdx.push(b);
  }
  const peakVal = new Float64Array(nFrames);
  const peakFreq = new Float64Array(nFrames);
  const scratch = new Array<number>(nBins - 1);
  const globalPeak = new Float64Array(nFrames);
  const med = new Float64Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    let bestB = bandIdx[0];
    let bestV = -1;
    for (const b of bandIdx) {
      const v = spec[f * nBins + b];
      if (v > bestV) {
        bestV = v;
        bestB = b;
      }
    }
    peakVal[f] = bestV;
    peakFreq[f] = freqAt(bestB);
    let gp = -1;
    for (let b = 1; b < nBins; b++) {
      const v = spec[f * nBins + b];
      scratch[b - 1] = v;
      if (v > gp) gp = v;
    }
    globalPeak[f] = gp;
    med[f] = Math.max(medianOf(scratch), 1e-6);
  }
  const dcDom = dcDominant(spec, nFrames, nBins);
  const harm = harmonicMask(spec, nFrames, nBins, df, peakFreq, peakVal);
  const isTone = new Uint8Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    if (
      peakVal[f] / med[f] >= TONE_PROMINENCE &&
      peakVal[f] >= globalPeak[f] &&
      frameRms[f] >= TONE_MIN_RMS &&
      !harm[f] &&
      !dcDom[f]
    ) {
      isTone[f] = 1;
    }
  }

  const lowBins: number[] = [];
  for (let b = 0; b < nBins; b++) {
    if (freqAt(b) <= HUM_LOW_HZ && b !== 0) lowBins.push(b);
  }
  const isHum = new Uint8Array(nFrames);
  for (let f = 0; f < nFrames; f++) {
    let lowEnergy = 0;
    let totalEnergy = 0;
    for (const b of lowBins) lowEnergy += spec[f * nBins + b] ** 2;
    for (let b = 1; b < nBins; b++) totalEnergy += spec[f * nBins + b] ** 2;
    if (
      lowEnergy / Math.max(totalEnergy, 1e-9) >= HUM_RATIO &&
      frameRms[f] >= HUM_MIN_RMS &&
      !dcDom[f]
    ) {
      isHum[f] = 1;
    }
  }

  const iv = trackRuns(isTone, frameT, TONE_MIN_FRAMES);
  iv.push(...trackRuns(isHum, frameT, HUM_MIN_FRAMES));
  iv.sort((a, b) => a[0] - b[0]);
  return iv.map(([a, b]) => [roundN(a, 3), roundN(b, 3)] as [number, number]);
}

// ---------- 内部丢包检测（packet_loss.py detect_packet_loss 的最小移植） ----------
interface PacketLossInfo {
  totalLost: number;
  lossRatePct: number;
  lossEvents: { time: number; count: number }[];
  maxConsecutiveLoss: number;
}

function detectPacketLossInternal(packets: PacketMap, ssrc: number): PacketLossInfo {
  const pkts = getStreamPackets(packets, ssrc); // 按捕获时间序
  if (pkts.length < 2) {
    return { totalLost: 0, lossRatePct: 0, lossEvents: [], maxConsecutiveLoss: 0 };
  }
  const lossEvents: { time: number; count: number }[] = [];
  let maxConsecutive = 0;
  const missing = new Set<number>(); // 扩展序号空间里尚未到达的包
  const SEQ_SPACE = 1 << 16;
  const SEQ_BACKWARD = 1 << 15;
  let prevSeq = pkts[0].seq;
  let prevExt = prevSeq;
  let cycles = 0;
  for (let i = 1; i < pkts.length; i++) {
    const { time, seq } = pkts[i];
    const d = (seq - prevSeq) & (SEQ_SPACE - 1);
    if (d === 0) continue; // 同一 (ssrc, seq) 已去重，防御性跳过
    if (d < SEQ_BACKWARD) {
      // 前进（可能越过 65535→0 回绕）
      if (seq < prevSeq) cycles += 1;
      const ext = seq + cycles * SEQ_SPACE;
      const gap = ext - prevExt - 1;
      if (gap > 0) {
        for (let m = prevExt + 1; m < ext; m++) missing.add(m);
        lossEvents.push({ time, count: gap });
        maxConsecutive = Math.max(maxConsecutive, gap);
      }
      prevSeq = seq;
      prevExt = ext;
    } else {
      // 倒退 = 迟到的乱序包：若它在此前的缺口里，退还多记的丢包
      const ext = seq + cycles * SEQ_SPACE;
      if (missing.has(ext)) missing.delete(ext);
      else if (missing.has(ext - SEQ_SPACE)) missing.delete(ext - SEQ_SPACE);
    }
  }
  const totalLost = missing.size;
  const total = pkts.length + totalLost;
  const lossRate = total > 0 ? (totalLost / total) * 100 : 0;
  return {
    totalLost,
    lossRatePct: roundN(lossRate, 4),
    lossEvents,
    maxConsecutiveLoss: maxConsecutive,
  };
}

// ---------- 视频花屏风险 ----------
export function analyzeVideoQuality(packets: PacketMap, ssrc: number): VideoQualityResult {
  const result: VideoQualityResult = {
    packetCount: 0,
    totalLost: 0,
    lossRatePct: 0.0,
    maxConsecutiveLoss: 0,
    lossEvents: [],
    nalUnits: 0,
    idrCount: 0,
    spsCount: 0,
    ppsCount: 0,
    brokenNals: 0,
    idrIntervalMaxS: null,
    firstIdrS: null,
    estArtifactsMs: 0.0,
    decodeCheck: 'skipped',
    decodeErrors: null,
    ffmpegNote: '无 ffmpeg 校验（桌面端未集成 ffmpeg，仅 RTP 层证据）',
    rtpIntegrity: null,
    issues: [],
    verdict: 'ok',
  };

  const bySeq = packets.get(ssrc);
  if (!bySeq || bySeq.size === 0) {
    result.verdict = 'unknown';
    return result;
  }
  result.packetCount = bySeq.size;

  const loss = detectPacketLossInternal(packets, ssrc);
  result.totalLost = loss.totalLost;
  result.lossRatePct = loss.lossRatePct;
  result.maxConsecutiveLoss = loss.maxConsecutiveLoss;

  const sortedSeqs = [...bySeq.keys()].sort((a, b) => a - b);
  const ptCount = new Map<number, number>();
  for (const s of sortedSeqs) {
    const p = bySeq.get(s)!.pt;
    ptCount.set(p, (ptCount.get(p) ?? 0) + 1);
  }
  let mainPt = 0;
  let ptBest = -1;
  for (const [p, c] of ptCount) {
    if (c > ptBest) {
      ptBest = c;
      mainPt = p;
    }
  }
  result.rtpIntegrity = rtpIntegrityCheck(
    sortedSeqs.map((s) => ({ seq: s, ts: bySeq.get(s)!.rtpTs, pt: bySeq.get(s)!.pt })),
    0,
    mainPt,
    'frame',
  );
  const t0 = bySeq.get(sortedSeqs[0])!.time;
  const tEnd = bySeq.get(sortedSeqs[sortedSeqs.length - 1])!.time;
  result.durationS = roundN(tEnd - t0, 2);
  for (const { time, count } of loss.lossEvents.slice(0, MAX_EVENTS)) {
    result.lossEvents.push({ timeS: roundN(time - t0, 2), count });
  }

  // —— NAL 重组（FU-A/STAP-A），带完整性追踪 ——
  let nalCount = 0;
  const idrTimes: number[] = [];
  let broken = 0;
  let fuaBuffer: number[] | null = null;
  let fuaCorrupt = false;
  let prevSeq: number | null = null;

  const finishFua = (): void => {
    // 收尾当前 FU-A NAL：统计并按是否破损计数
    if (fuaBuffer === null) return;
    nalCount += 1;
    if (fuaCorrupt) broken += 1;
    fuaBuffer = null;
    fuaCorrupt = false;
  };

  for (const seq of sortedSeqs) {
    const rec = bySeq.get(seq)!;
    const payload = rec.payload;
    if (!payload || payload.length < 2) continue;
    const t = rec.time - t0;

    // seq 缺口落在 FU-A 分片中途 → 该 NAL 必然破损
    if (prevSeq !== null && fuaBuffer !== null) {
      const d = (seq - prevSeq) & 0xffff;
      if (1 < d && d < 0x8000) fuaCorrupt = true;
    }
    prevSeq = seq;

    const nalType = payload[0] & 0x1f;
    if (nalType === NAL_FU_A) {
      const fuHeader = payload[1];
      const startBit = fuHeader & 0x80;
      const endBit = fuHeader & 0x40;
      if (startBit) {
        if (fuaBuffer !== null) fuaCorrupt = true; // 上一 NAL 没等到结束分片
        finishFua();
        fuaBuffer = [(payload[0] & 0xe0) | (fuHeader & 0x1f)];
        for (let i = 2; i < payload.length; i++) fuaBuffer.push(payload[i]);
        if ((fuHeader & 0x1f) === NAL_IDR) idrTimes.push(t);
      } else if (fuaBuffer !== null) {
        for (let i = 2; i < payload.length; i++) fuaBuffer.push(payload[i]);
      } else if (endBit) {
        broken += 1; // 收到结尾分片但开头已丢（无法重组）
      }
      if (endBit && fuaBuffer !== null) finishFua();
    } else if (nalType === NAL_STAP_A) {
      let offset = 1;
      while (offset + 2 <= payload.length) {
        const naluSize = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        if (offset + naluSize > payload.length) {
          broken += 1; // STAP-A 内部 NAL 不完整
          break;
        }
        const innerType = payload[offset] & 0x1f;
        nalCount += 1;
        if (innerType === NAL_IDR) idrTimes.push(t);
        else if (innerType === NAL_SPS) result.spsCount += 1;
        else if (innerType === NAL_PPS) result.ppsCount += 1;
        offset += naluSize;
      }
    } else if (nalType < 24) {
      nalCount += 1;
      if (nalType === NAL_IDR) idrTimes.push(t);
      else if (nalType === NAL_SPS) result.spsCount += 1;
      else if (nalType === NAL_PPS) result.ppsCount += 1;
    }
  }
  finishFua();

  result.nalUnits = nalCount;
  result.idrCount = idrTimes.length;
  result.brokenNals = broken;
  if (idrTimes.length) {
    result.firstIdrS = roundN(idrTimes[0], 2);
    let maxGap = 0;
    for (let i = 1; i < idrTimes.length; i++) {
      maxGap = Math.max(maxGap, idrTimes[i] - idrTimes[i - 1]);
    }
    result.idrIntervalMaxS = roundN(maxGap, 2);
  }

  // —— 丢包 → 花屏影响估算：每次丢包花到下一个 IDR 刷新为止 ——
  let artifact = 0.0;
  for (const ev of result.lossEvents) {
    let k = 0;
    while (k < idrTimes.length && idrTimes[k] <= ev.timeS) k++; // bisect_right
    const until = k < idrTimes.length ? idrTimes[k] : tEnd;
    artifact += Math.max(until - ev.timeS, 0);
  }
  if (result.totalLost && idrTimes.length === 0) {
    artifact = tEnd - t0; // 全程无关键帧：丢包影响无法自愈
  }
  result.estArtifactsMs = roundN(artifact * 1000, 1);

  // 桌面端没有 ffmpeg：解码校验跳过（decodeCheck 恒为 'skipped'），见 ffmpegNote

  result.issues = videoIssues(result);
  const worst = new Set(result.issues.map((i) => i.severity));
  result.verdict = worst.has('critical') ? 'bad' : worst.has('warning') ? 'risk' : 'ok';
  return result;
}

function videoIssues(r: VideoQualityResult): QualityIssue[] {
  const issues: QualityIssue[] = [];
  const integ = r.rtpIntegrity;
  if (integ?.tsBackward) {
    issues.push({
      kind: 'rtp_order',
      severity: 'critical',
      message:
        `RTP 时间戳倒退 ${integ.tsBackward} 处——发送端时钟异常，按序号重组的视频帧与真实播放序错位，` +
        `花屏/卡顿风险高`,
    });
  }
  if (r.brokenNals) {
    issues.push({
      kind: 'broken_nal',
      severity: 'critical',
      message:
        `${r.brokenNals} 个视频帧数据因丢包/分片不完整而破损——解码必然出错，对应画面会出现花屏、马赛克或绿屏`,
    });
  }
  if (r.decodeCheck === 'errors' && r.decodeErrors) {
    issues.push({
      kind: 'decode_errors',
      severity: 'critical',
      message: `ffmpeg 对重建裸流试解码报 ${r.decodeErrors} 处错误——码流确实损坏，与花屏现象直接对应`,
    });
  }
  const lost = r.totalLost;
  if (lost && r.lossRatePct >= 1.0) {
    issues.push({
      kind: 'video_loss',
      severity: 'critical',
      message:
        `视频流丢包 ${lost} 包（${r.lossRatePct.toFixed(2)}%），丢包处画面会花屏直到关键帧刷新，` +
        `估算累计花屏影响 ${(r.estArtifactsMs / 1000).toFixed(1)} 秒`,
    });
  } else if (lost) {
    issues.push({
      kind: 'video_loss',
      severity: 'warning',
      message:
        `视频流丢包 ${lost} 包（${r.lossRatePct.toFixed(2)}%）——少量视频丢包就会在丢包时刻出现` +
        `短暂马赛克/花屏（估算累计影响 ${(r.estArtifactsMs / 1000).toFixed(1)} 秒），` +
        `音频丢同样数量则几乎无感`,
    });
  }
  if (r.idrCount === 0 && r.nalUnits && (r.durationS ?? 0) >= 10) {
    issues.push({
      kind: 'no_idr',
      severity: 'warning',
      message:
        '整个抓包未见到关键帧（IDR）——一旦丢包画面无法自行恢复，花屏会持续到挂断；请检查终端关键帧间隔配置',
    });
  } else if (r.idrIntervalMaxS !== null && r.idrIntervalMaxS > 10) {
    issues.push({
      kind: 'idr_gap',
      severity: 'info',
      message:
        `关键帧间隔最长 ${Math.round(r.idrIntervalMaxS)} 秒——间隔越长，每次丢包后的花屏持续越久，` +
        `建议终端把关键帧间隔控制在 2~4 秒`,
    });
  }
  return issues;
}
