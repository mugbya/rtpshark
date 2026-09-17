// 媒体重建（media_extractor.py 的 TS 移植 —— 桌面端全内存版）
// 与 Python 版的差异（桌面端适配，无文件系统、无 ffmpeg）：
// - 不写磁盘：audio 条目带 wavBytes（内存拼好的 8kHz/16bit 单声道 WAV，
//   G.711 PCMU(PT=0)/PCMA(PT=8) 解码为 16bit PCM）；
//   video 条目带 h264Bytes（RFC 6184 去分片后的 Annex B 裸流）；
// - MP4：无 ffmpeg，改用 mp4-muxer 纯 JS 封装（从带内 SPS/PPS 拼 avcC、
//   Annex B → 长度前缀样本）；SPS/PPS 缺失或解析失败时静默降级只留裸流；
// - OPUS 等其他编码在 Python 版靠 ffmpeg 解码，桌面端不可用，列入
//   unsupported（错误文案沿用 Python 的"未检测到 ffmpeg"口径）；
// - get_media_urls 在桌面端不需要 URL，跳过；media_manifest.json 落盘跳过。
import { Muxer, ArrayBufferTarget } from 'mp4-muxer';
import type {
  CallInfo,
  Capture,
  ClassifiedStreams,
  PacketMap,
  RtpPacketRec,
  StreamInfo,
} from './types';
import { getPtName } from './streamClassifier';
import { signed32 } from './rtpParser';
import type { SipFlowItem } from './callDetector';

// ---------------- 音频编码常量 ----------------

export const PT_PCMU = 0; // G.711 μ-law
export const PT_PCMA = 8; // G.711 A-law

// G.711 打包：通常 20ms/包 = 8kHz 下 160 样本
export const G711_SAMPLES_PER_PACKET = 160;
export const G711_SAMPLE_RATE = 8000;

// ---------------- 清单类型 ----------------

export type MediaDirection = 'inbound' | 'outbound' | 'unknown';

/** 媒体收发一端（谁到谁标注） */
export interface MediaPartyEndpoint {
  label: string;
  ip: string | null;
}

/** 媒体的真实发送/接收方：呼入 = 对端 → 本抓包点，呼出反之 */
export interface MediaFlow {
  from: MediaPartyEndpoint;
  to: MediaPartyEndpoint;
}

export interface PartyNode {
  label: string;
  ip: string;
}

/** 通话拓扑行：主叫 ↔ FS ↔ 被叫（各端称呼 + IP），无信令时缺省 */
export interface PartyChain {
  caller: PartyNode | null;
  answerer: PartyNode | null;
  serverIp: string | null;
}

export interface AudioMediaEntry {
  callId: string | null;
  role: string;
  direction: MediaDirection;
  ssrc: string; // '0x…' 字符串
  codec: string;
  pt: number | null;
  durationMs: number;
  totalPackets: number;
  lostPackets: number;
  packetDurationMs?: number;
  tsGapFilled: number;
  /** 供 UI 播放列表用（durationMs / 1000） */
  durationSec: number;
  /** 内存重建的 WAV 容器（8kHz/16bit/单声道 PCM） */
  wavBytes: Uint8Array;
  /** 谁到谁（如 '主叫 → FS'），describeMediaParties 填写 */
  label?: string;
  flow?: MediaFlow;
}

export interface VideoMediaEntry {
  callId: string | null;
  role: string;
  direction: MediaDirection;
  ssrc: string; // '0x…' 字符串
  codec: string;
  pt: number | null;
  totalPackets: number;
  nalUnits: number;
  fuaFragments: number;
  /** 按 RTP 时间戳增量（90kHz 时钟）估算的媒体时长（秒） */
  durationSec: number;
  /** RFC 6184 去分片后的 Annex B 裸流 */
  h264Bytes: Uint8Array;
  /** mp4-muxer 封装成功时的 MP4 字节；失败静默降级，仅留裸流 */
  mp4Bytes?: Uint8Array;
  mp4Available: boolean;
  mp4Error?: string | null;
  label?: string;
  flow?: MediaFlow;
}

export interface UnsupportedMediaEntry {
  role: string;
  ssrc: string;
  codec: string;
  reason: string;
  label?: string;
  flow?: MediaFlow;
}

export interface MediaManifest {
  callId: string | null;
  audio: AudioMediaEntry[];
  video: VideoMediaEntry[];
  unsupported: UnsupportedMediaEntry[];
  /** describeMediaParties 填写：本批媒体涉及的通话拓扑（按主被叫去重） */
  parties?: PartyChain[];
}

// ---------------- 方向判定 ----------------

/** 抓包点相对方向：'outbound' = 抓包点发出的媒体，'inbound' = 收到的媒体。
 * FS 抓包：dst==server 为到 FS → inbound；端点抓包：dst==server 为发往
 * 服务器 → outbound。与 Python _endpoint_direction 一致。 */
export function endpointDirection(
  dstIp: string,
  serverIp: string | null,
  role: string,
): MediaDirection {
  if (!serverIp) return 'unknown';
  if (role === 'fs') return dstIp === serverIp ? 'inbound' : 'outbound';
  return dstIp === serverIp ? 'outbound' : 'inbound';
}

// ---------------- G.711 解码（audioop.ulaw2lin/alaw2lin 等价实现） ----------------

/** ITU G.711 μ-law 字节 → 16bit 线性 PCM（与 audioop.st_ulaw2linear16 一致） */
export function ulawToLinear16(uVal: number): number {
  uVal = ~uVal & 0xff;
  let t = ((uVal & 0x0f) << 3) + 0x84;
  t <<= (uVal & 0x70) >> 4;
  return (uVal & 0x80) ? 0x84 - t : t - 0x84;
}

/** ITU G.711 A-law 字节 → 16bit 线性 PCM（与 audioop.st_alaw2linear16 一致） */
export function alawToLinear16(aVal: number): number {
  aVal ^= 0x55;
  let t = (aVal & 0x0f) << 4;
  const seg = (aVal & 0x70) >> 4;
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
      break;
  }
  return (aVal & 0x80) ? t : -t;
}

/** 解码一包 G.711 载荷为 16bit 线性采样 */
export function decodeG711(payload: Uint8Array, pt: number): Int16Array {
  const out = new Int16Array(payload.length);
  if (pt === PT_PCMU) {
    for (let i = 0; i < payload.length; i++) out[i] = ulawToLinear16(payload[i]);
  } else {
    for (let i = 0; i < payload.length; i++) out[i] = alawToLinear16(payload[i]);
  }
  return out;
}

// ---------------- WAV 容器（wave 模块等价的 PCM WAV 头） ----------------

/** 把单声道 16bit PCM 打包成 WAV（RIFF）容器字节 */
export function buildWavBytes(pcm: Int16Array, sampleRate = G711_SAMPLE_RATE): Uint8Array {
  const dataLen = pcm.length * 2;
  const buf = new Uint8Array(44 + dataLen);
  const dv = new DataView(buf.buffer);
  const writeStr = (off: number, s: string) => {
    for (let i = 0; i < s.length; i++) buf[off + i] = s.charCodeAt(i);
  };
  writeStr(0, 'RIFF');
  dv.setUint32(4, 36 + dataLen, true);
  writeStr(8, 'WAVE');
  writeStr(12, 'fmt ');
  dv.setUint32(16, 16, true); // fmt 块长
  dv.setUint16(20, 1, true); // PCM
  dv.setUint16(22, 1, true); // 单声道
  dv.setUint32(24, sampleRate, true);
  dv.setUint32(28, sampleRate * 2, true); // byteRate
  dv.setUint16(32, 2, true); // blockAlign
  dv.setUint16(34, 16, true); // bitsPerSample
  writeStr(36, 'data');
  dv.setUint32(40, dataLen, true);
  for (let i = 0; i < pcm.length; i++) dv.setInt16(44 + i * 2, pcm[i], true);
  return buf;
}

// ---------------- 通用辅助 ----------------

/** 取某 SSRC 带载荷的包（按 seq 索引），对应 Python 的 stream_pkts 收集 */
function collectStream(
  packets: PacketMap,
  ssrc: number,
): Map<number, RtpPacketRec> {
  const out = new Map<number, RtpPacketRec>();
  const bySeq = packets.get(ssrc);
  if (!bySeq) return out;
  for (const [seq, v] of bySeq) {
    if (v.payload !== undefined) out.set(seq, v);
  }
  return out;
}

/** 出现最多的 PT（Python max(pt_counts, key=…) 语义：并列取先见者） */
function dominantPt(streamPkts: Map<number, RtpPacketRec>): number {
  const counts = new Map<number, number>();
  let best = 0;
  let bestN = -1;
  for (const v of streamPkts.values()) {
    const n = (counts.get(v.pt) ?? 0) + 1;
    counts.set(v.pt, n);
    if (n > bestN) {
      bestN = n;
      best = v.pt;
    }
  }
  return best;
}

/** 单包媒体时长（样本数）：以 RTP 时间戳增量中位数实测为准 */
function medianSpp(
  streamPkts: Map<number, RtpPacketRec>,
  sortedSeqs: number[],
  clock: number,
  fallback: number,
): number {
  const deltas: number[] = [];
  for (let i = 1; i < sortedSeqs.length; i++) {
    const d = signed32(
      streamPkts.get(sortedSeqs[i])!.rtpTs -
      streamPkts.get(sortedSeqs[i - 1])!.rtpTs,
    );
    if (d > 0) deltas.push(d);
  }
  deltas.sort((a, b) => a - b);
  let spp = deltas.length ? deltas[Math.floor(deltas.length / 2)] : 0;
  if (!(spp > 0 && spp <= clock / 2)) spp = fallback; // 单包不超过半秒
  return spp;
}

const round1 = (x: number) => Math.round(x * 10) / 10;

// ---------------- 音频重建 ----------------

export interface AudioReconstructResult {
  ssrc: string;
  pt: number | null;
  codec: string;
  sampleRate: number;
  durationMs: number;
  totalPackets: number;
  lostPackets: number;
  silenceFilled: number;
  samplesPerPacket: number;
  packetDurationMs: number;
  tsGapFilled: number;
  tsExtraSilenceMs: number;
  success: boolean;
  direction: MediaDirection;
  error: string | null;
  wavBytes: Uint8Array | null;
}

/** 从 RTP 包重建一条音频流的 WAV 字节（reconstruct_audio 的全内存版） */
export function reconstructAudio(
  packets: PacketMap,
  ssrc: number,
  serverIp: string | null,
  role: string | null,
  codecName: string | null = null,
): AudioReconstructResult {
  const result: AudioReconstructResult = {
    ssrc: `0x${(ssrc >>> 0).toString(16).padStart(8, '0')}`,
    pt: null,
    codec: 'unknown',
    sampleRate: G711_SAMPLE_RATE,
    durationMs: 0,
    totalPackets: 0,
    lostPackets: 0,
    silenceFilled: 0,
    samplesPerPacket: G711_SAMPLES_PER_PACKET,
    packetDurationMs: 20.0,
    tsGapFilled: 0,
    tsExtraSilenceMs: 0.0,
    success: false,
    direction: 'unknown',
    error: null,
    wavBytes: null,
  };

  const streamPkts = collectStream(packets, ssrc);
  if (!streamPkts.size) {
    result.error = 'No packets with payload found for this SSRC';
    return result;
  }

  const pt = dominantPt(streamPkts);
  result.pt = pt;
  result.codec = codecName || getPtName(pt);

  const firstPkt = streamPkts.values().next().value as RtpPacketRec;
  result.direction = endpointDirection(firstPkt.dstIp, serverIp, role ?? '');

  const isOpus = (result.codec || '').toUpperCase().startsWith('OPUS');
  if (pt !== PT_PCMU && pt !== PT_PCMA && !isOpus) {
    result.error =
      `Codec ${result.codec} is not supported for reconstruction. ` +
      '桌面端仅支持 PCMU/PCMA 直接重建（无 ffmpeg）';
    return result;
  }

  // Python 版 OPUS 走 Ogg Opus 封装 + ffmpeg 解码；桌面端无 ffmpeg，
  // 只补齐包统计骨架后按"未检测到 ffmpeg"口径报错
  const sortedSeqs = [...streamPkts.keys()].sort((a, b) => a - b);
  result.totalPackets = sortedSeqs.length;
  if (isOpus) {
    result.error = 'OPUS 音频需要 ffmpeg 解码（未检测到 ffmpeg）';
    return result;
  }

  // 每包媒体时长以 RTP 时间戳实测为准（设备包化不一定是 20ms/160 样本）
  const spp = medianSpp(streamPkts, sortedSeqs, G711_SAMPLE_RATE, G711_SAMPLES_PER_PACKET);
  result.samplesPerPacket = spp;
  result.packetDurationMs = round1((spp / G711_SAMPLE_RATE) * 1000);

  // 检测缺口并补静音
  const chunks: Int16Array[] = [];
  let prevSeq = sortedSeqs[0] - 1;
  let prevTs: number | null = null;
  let tsGapFilled = 0;
  let tsExtraSilenceMs = 0.0;

  for (const seq of sortedSeqs) {
    const pkt = streamPkts.get(seq)!;
    const ts = pkt.rtpTs;
    const gap = (seq - prevSeq - 1) & 0xffff;
    let expectedAdvance = spp;
    if (gap > 0 && gap < 100) { // 合理缺口（非 seq 回绕）
      expectedAdvance = (gap + 1) * spp;
      chunks.push(new Int16Array(gap * spp));
      result.silenceFilled += gap;
      result.lostPackets += gap;
    }

    // 时间戳缺口：seq 连续但媒体时间断档（静音抑制/时间戳跳变）时，
    // 按 ts 实测缺口补静音，否则重建音频会比真实通话短
    if (prevTs !== null) {
      const excess = signed32(ts - prevTs) - expectedAdvance;
      if (spp > 0 && excess > Math.floor(spp / 2)) {
        if (excess <= G711_SAMPLE_RATE * 5) { // 超过 5s 视为时间戳重置，不补
          chunks.push(new Int16Array(excess));
          tsGapFilled += 1;
          tsExtraSilenceMs += (excess / G711_SAMPLE_RATE) * 1000;
        } else {
          tsGapFilled += 1;
        }
      }
    }

    const rawPayload = pkt.payload as Uint8Array;
    if (pkt.pt !== pt) {
      // 非 main PT 包（如 RFC 4733 DTMF telephone-event，载荷仅 4 字节
      // 事件描述）不能按主 PT 解码——按原样解会产出垃圾采样，听感为
      // 轻微咔哒；置零，时间线由上方 ts 缺口补偿逻辑对齐
      chunks.push(new Int16Array(rawPayload.length));
    } else {
      chunks.push(decodeG711(rawPayload, pt));
    }

    prevSeq = seq;
    prevTs = ts;
  }

  result.tsGapFilled = tsGapFilled;
  result.tsExtraSilenceMs = round1(tsExtraSilenceMs);

  let total = 0;
  for (const c of chunks) total += c.length;
  result.durationMs = (total / G711_SAMPLE_RATE) * 1000;

  const pcm = new Int16Array(total);
  let off = 0;
  for (const c of chunks) {
    pcm.set(c, off);
    off += c.length;
  }
  result.wavBytes = buildWavBytes(pcm, G711_SAMPLE_RATE);
  result.success = true;
  return result;
}

// ---------------- 视频重建（H.264 RFC 6184 去分片） ----------------

const NAL_TYPE_STAP_A = 24;
const NAL_TYPE_FU_A = 28;

/** 去分片后的单个 NAL（带其所属 RTP 包的时间戳，供 MP4 封装分组） */
export interface NalUnit {
  data: Uint8Array;
  ts: number;
}

export interface VideoReconstructResult {
  ssrc: string;
  pt: number | null;
  codec: string;
  totalPackets: number;
  nalUnits: number;
  fuaFragments: number;
  success: boolean;
  direction: MediaDirection;
  error: string | null;
  /** Annex B 裸流（带 00000001 起始码） */
  h264Bytes: Uint8Array | null;
  /** 去分片后的 NAL 序列（含 SPS/PPS），供 MP4 封装使用 */
  nals: NalUnit[];
  /** 按 RTP 时间戳增量（90kHz）估算的媒体时长（秒） */
  durationSec: number;
}

export const VIDEO_CLOCK_RATE = 90000;

export function reconstructVideoRaw(
  packets: PacketMap,
  ssrc: number,
  serverIp: string | null,
  role: string | null,
  codecName: string | null = null,
): VideoReconstructResult {
  const result: VideoReconstructResult = {
    ssrc: `0x${(ssrc >>> 0).toString(16).padStart(8, '0')}`,
    pt: null,
    codec: 'unknown',
    totalPackets: 0,
    nalUnits: 0,
    fuaFragments: 0,
    success: false,
    direction: 'unknown',
    error: null,
    h264Bytes: null,
    nals: [],
    durationSec: 0,
  };

  const streamPkts = collectStream(packets, ssrc);
  if (!streamPkts.size) {
    result.error = 'No packets with payload found for this SSRC';
    return result;
  }

  const pt = dominantPt(streamPkts);
  result.pt = pt;
  result.codec = codecName || getPtName(pt);

  const firstPkt = streamPkts.values().next().value as RtpPacketRec;
  result.direction = endpointDirection(firstPkt.dstIp, serverIp, role ?? '');

  const sortedSeqs = [...streamPkts.keys()].sort((a, b) => a - b);
  result.totalPackets = sortedSeqs.length;

  // 媒体时长：RTP 时间戳正增量累计 / 90kHz
  let span = 0;
  let prevTs: number | null = null;
  for (const seq of sortedSeqs) {
    const ts = streamPkts.get(seq)!.rtpTs;
    if (prevTs !== null) {
      const d = signed32(ts - prevTs);
      if (d > 0) span += d;
    }
    prevTs = ts;
  }
  result.durationSec = span / VIDEO_CLOCK_RATE;

  const nalUnits: NalUnit[] = [];
  let fuaBuffer: number[] | null = null;
  let fuaTs = 0;

  for (const seq of sortedSeqs) {
    const pkt = streamPkts.get(seq)!;
    const payload = pkt.payload as Uint8Array;
    if (payload.length < 2) continue;

    const nalType = payload[0] & 0x1f;

    if (nalType === NAL_TYPE_FU_A) {
      // FU-A 分片单元
      result.fuaFragments += 1;
      const fuIndicator = payload[0];
      const fuHeader = payload[1];
      const startBit = fuHeader & 0x80;
      const endBit = fuHeader & 0x40;
      const fuNalType = fuHeader & 0x1f;

      if (startBit) {
        // 新的分片 NAL 起始：重建 NAL 头
        fuaBuffer = [(fuIndicator & 0xe0) | fuNalType];
        for (let i = 2; i < payload.length; i++) fuaBuffer.push(payload[i]);
        fuaTs = pkt.rtpTs;
      } else if (fuaBuffer !== null) {
        for (let i = 2; i < payload.length; i++) fuaBuffer.push(payload[i]);
      }

      if (endBit && fuaBuffer !== null) {
        nalUnits.push({ data: Uint8Array.from(fuaBuffer), ts: fuaTs });
        fuaBuffer = null;
        result.nalUnits += 1;
      }
    } else if (nalType === NAL_TYPE_STAP_A) {
      // STAP-A 聚合包 —— 拆出各 NAL
      let offset = 1;
      while (offset + 2 <= payload.length) {
        const naluSize = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        if (offset + naluSize <= payload.length) {
          nalUnits.push({ data: payload.slice(offset, offset + naluSize), ts: pkt.rtpTs });
          result.nalUnits += 1;
          offset += naluSize;
        } else {
          break;
        }
      }
    } else if (nalType < 24) {
      // 单 NAL 包
      nalUnits.push({ data: payload.slice(), ts: pkt.rtpTs });
      result.nalUnits += 1;
    }
    // NAL types 25-31 为保留/未定义，跳过
  }

  // 收尾残留的 FU-A 缓冲
  if (fuaBuffer !== null) {
    nalUnits.push({ data: Uint8Array.from(fuaBuffer), ts: fuaTs });
    result.nalUnits += 1;
  }

  if (!nalUnits.length) {
    result.error = 'No valid NAL units extracted';
    return result;
  }

  result.nals = nalUnits;

  // Annex B 裸流（起始码 + NAL）
  let total = 0;
  for (const n of nalUnits) total += 4 + n.data.length;
  const annexB = new Uint8Array(total);
  let off = 0;
  for (const n of nalUnits) {
    annexB[off] = 0; annexB[off + 1] = 0; annexB[off + 2] = 0; annexB[off + 3] = 1;
    off += 4;
    annexB.set(n.data, off);
    off += n.data.length;
  }
  result.h264Bytes = annexB;
  result.success = true;
  return result;
}

// ---------------- MP4 封装（mp4-muxer，失败静默降级） ----------------

/** 去除 H.264 NAL 中的防竞争字节（00 00 03 → 00 00），得到 RBSP */
function unescapeRbsp(nal: Uint8Array): Uint8Array {
  const out = new Uint8Array(nal.length);
  let len = 0;
  let zeros = 0;
  for (let i = 0; i < nal.length; i++) {
    const b = nal[i];
    if (zeros === 2 && b === 0x03 && i + 1 < nal.length && nal[i + 1] <= 3) {
      zeros = 0;
      continue;
    }
    zeros = b === 0 ? zeros + 1 : 0;
    out[len++] = b;
  }
  return out.subarray(0, len);
}

/** Exp-Golomb 比特读取器 */
class BitReader {
  private pos = 0;
  private readonly buf: Uint8Array;

  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  readBit(): number {
    const byte = this.buf[this.pos >> 3];
    this.pos += 1;
    return (byte >> (7 - (this.pos - 1) % 8)) & 1;
  }

  readBits(n: number): number {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | this.readBit();
    return v;
  }

  readUe(): number {
    let zeros = 0;
    while (this.readBit() === 0) {
      zeros += 1;
      if (zeros > 32) throw new Error('bad ue');
    }
    return (1 << zeros) - 1 + (zeros ? this.readBits(zeros) : 0);
  }

  readSe(): number {
    const ue = this.readUe();
    return ue & 1 ? (ue + 1) / 2 : -(ue / 2);
  }
}

/** 解析 SPS 得出视频宽高；任何解析失败返回 null（调用方放弃封 MP4） */
export function parseSpsDimensions(
  spsNal: Uint8Array,
): { width: number; height: number } | null {
  try {
    const rbsp = unescapeRbsp(spsNal);
    const r = new BitReader(rbsp);
    r.readBits(8); // profile_idc（NAL 头后的第一个字节起）
    r.readBits(16); // 约束标志 + level_idc
    const profileIdc = spsNal[1];
    r.readUe(); // seq_parameter_set_id
    let chromaFormatIdc = 1;
    let separateColourPlaneFlag = 0;
    const HIGH_PROFILES = new Set([
      100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135,
    ]);
    if (HIGH_PROFILES.has(profileIdc)) {
      chromaFormatIdc = r.readUe();
      if (chromaFormatIdc === 3) separateColourPlaneFlag = r.readBit();
      r.readUe(); // bit_depth_luma_minus8
      r.readUe(); // bit_depth_chroma_minus8
      r.readBit(); // qpprime_y_zero_transform_bypass_flag
      if (r.readBit()) {
        // seq_scaling_matrix_present_flag → 跳过 scaling list
        const listCount = chromaFormatIdc !== 3 ? 8 : 12;
        for (let i = 0; i < listCount; i++) {
          if (r.readBit()) {
            const size = i < 6 ? 16 : 64;
            let lastScale = 8;
            let nextScale = 8;
            for (let j = 0; j < size; j++) {
              if (nextScale !== 0) {
                const delta = r.readSe();
                nextScale = (lastScale + delta + 256) % 256;
              }
              if (nextScale !== 0) lastScale = nextScale;
            }
          }
        }
      }
    }
    r.readUe(); // log2_max_frame_num_minus4
    const pocType = r.readUe();
    if (pocType === 0) {
      r.readUe(); // log2_max_pic_order_cnt_lsb_minus4
    } else if (pocType === 1) {
      r.readBit(); // delta_pic_order_always_zero_flag
      r.readSe(); // offset_for_non_ref_pic
      r.readSe(); // offset_for_top_to_bottom_field
      const n = r.readUe();
      for (let i = 0; i < n; i++) r.readSe();
    }
    r.readUe(); // max_num_ref_frames
    r.readBit(); // gaps_in_frame_num_value_allowed_flag
    const picWidthInMbs = r.readUe() + 1;
    const picHeightInMapUnits = r.readUe() + 1;
    const frameMbsOnlyFlag = r.readBit();
    if (!frameMbsOnlyFlag) r.readBit(); // mb_adaptive_frame_field_flag
    r.readBit(); // direct_8x8_inference_flag
    let cropL = 0, cropR = 0, cropT = 0, cropB = 0;
    if (r.readBit()) {
      cropL = r.readUe();
      cropR = r.readUe();
      cropT = r.readUe();
      cropB = r.readUe();
    }
    let width = picWidthInMbs * 16;
    let height = (2 - frameMbsOnlyFlag) * picHeightInMapUnits * 16;
    const chromaArrayType = separateColourPlaneFlag ? 0 : chromaFormatIdc;
    let cropUnitX: number;
    let cropUnitY: number;
    if (chromaArrayType === 0) {
      cropUnitX = 1;
      cropUnitY = 2 - frameMbsOnlyFlag;
    } else {
      const subW = chromaFormatIdc === 3 ? 1 : 2;
      const subH = chromaFormatIdc === 1 ? 2 : 1;
      cropUnitX = subW;
      cropUnitY = subH * (2 - frameMbsOnlyFlag);
    }
    width -= cropUnitX * (cropL + cropR);
    height -= cropUnitY * (cropT + cropB);
    if (width <= 0 || height <= 0 || width > 10000 || height > 10000) return null;
    return { width, height };
  } catch {
    return null;
  }
}

/** 从 SPS/PPS 拼 avcC（AVCDecoderConfigurationRecord） */
function buildAvcC(sps: Uint8Array, pps: Uint8Array): Uint8Array {
  const out = new Uint8Array(11 + sps.length + pps.length);
  const dv = new DataView(out.buffer);
  out[0] = 1; // configurationVersion
  out[1] = sps[1]; // AVCProfileIndication
  out[2] = sps[2]; // profile_compatibility
  out[3] = sps[3]; // level_idc
  out[4] = 0xff; // lengthSizeMinusOne = 3（4 字节长度前缀）
  out[5] = 0xe1; // numOfSPS = 1
  dv.setUint16(6, sps.length);
  out.set(sps, 8);
  const p = 8 + sps.length;
  out[p] = 1; // numOfPPS = 1
  dv.setUint16(p + 1, pps.length);
  out.set(pps, p + 3);
  return out;
}

/** 把去分片 NAL 序列封成 MP4；SPS/PPS 缺失或封装失败返回 null（静默降级） */
export function tryMuxH264ToMp4(nals: NalUnit[]): Uint8Array | null {
  let sps: Uint8Array | null = null;
  let pps: Uint8Array | null = null;
  for (const n of nals) {
    const t = n.data[0] & 0x1f;
    if (t === 7 && !sps) sps = n.data;
    else if (t === 8 && !pps) pps = n.data;
  }
  if (!sps || !pps) return null;
  const dims = parseSpsDimensions(sps);
  if (!dims) return null;

  try {
    // 按 RTP 时间戳把 NAL 聚成一帧帧样本（SPS/PPS 进 avcC，不作样本）
    interface Frame { data: Uint8Array[]; ts: number; key: boolean }
    const frames: Frame[] = [];
    const pushNal = (data: Uint8Array, ts: number, key: boolean) => {
      const last = frames[frames.length - 1];
      if (last && last.ts === ts) {
        last.data.push(data);
        last.key = last.key || key;
      } else {
        frames.push({ data: [data], ts, key });
      }
    };
    for (const n of nals) {
      const t = n.data[0] & 0x1f;
      if (t === 7 || t === 8) continue; // SPS/PPS → avcC
      pushNal(n.data, n.ts, t === 5);
    }
    if (!frames.length) return null;

    const baseTs = frames[0].ts;
    const avcC = buildAvcC(sps, pps);
    const muxer = new Muxer({
      target: new ArrayBufferTarget(),
      fastStart: 'in-memory',
      video: { codec: 'avc', width: dims.width, height: dims.height },
    });
    let prevT = 0;
    let prevDur = 1 / 30;
    for (let i = 0; i < frames.length; i++) {
      const f = frames[i];
      // Annex B → 4 字节长度前缀
      let len = 0;
      for (const d of f.data) len += 4 + d.length;
      const sample = new Uint8Array(len);
      const dv = new DataView(sample.buffer);
      let off = 0;
      for (const d of f.data) {
        dv.setUint32(off, d.length);
        off += 4;
        sample.set(d, off);
        off += d.length;
      }
      let t = signed32(f.ts - baseTs) / VIDEO_CLOCK_RATE;
      if (t < prevT) t = prevT;
      const dur = i + 1 < frames.length
        ? Math.max(prevDur, (() => { const nt = signed32(frames[i + 1].ts - baseTs) / VIDEO_CLOCK_RATE; return nt > t ? nt - t : prevDur; })())
        : prevDur;
      const meta = i === 0
        ? ({ decoderConfig: { description: avcC } } as unknown as EncodedVideoChunkMetadata)
        : undefined;
      muxer.addVideoChunkRaw(sample, f.key ? 'key' : 'delta', t, dur, meta);
      prevT = t;
      prevDur = dur;
    }
    muxer.finalize();
    return new Uint8Array(muxer.target.buffer);
  } catch {
    return null; // 静默降级：只留裸流
  }
}

// ---------------- 生成全量媒体清单 ----------------

export function generateAllMedia(
  captures: Record<string, Capture>,
  classified: ClassifiedStreams,
  serverIp: string | null,
  mediaTypes: 'audio' | 'video' | 'all' = 'all',
  opts: { ssrcFilter?: Set<number>; callId?: string | null } = {},
): MediaManifest {
  const manifest: MediaManifest = {
    callId: opts.callId ?? null,
    audio: [],
    video: [],
    unsupported: [],
  };
  const roles = Object.keys(captures);
  const unsupportedSeen = new Set<string>();
  const callId = manifest.callId;

  // 音频流：对每份抓包中出现的每个 (抓包, SSRC) 组合单独重建。同一条流
  // 在不同抓包点（如 FS 与终端）各出一份文件，各自标注角色与相对方向。
  if (mediaTypes === 'audio' || mediaTypes === 'all') {
    for (const [ssrcKey, info] of Object.entries(classified.audio)) {
      const ssrc = Number(ssrcKey);
      if (opts.ssrcFilter && !opts.ssrcFilter.has(ssrc)) continue;
      // SDP rtpmap 解析出的编码名：动态 PT（如 OPUS@96）只看 PT 号
      // 识别不出编码，重建与展示都靠它
      const codecName = info?.codec ?? null;
      for (const role of roles) {
        const cap = captures[role];
        if (!cap || !(ssrc in cap.streams)) continue;
        const res = reconstructAudio(cap.packets, ssrc, serverIp, role, codecName);
        if (res.success && res.wavBytes) {
          manifest.audio.push({
            callId,
            role,
            direction: res.direction,
            ssrc: res.ssrc,
            codec: res.codec,
            pt: res.pt,
            durationMs: round1(res.durationMs),
            totalPackets: res.totalPackets,
            lostPackets: res.lostPackets,
            packetDurationMs: res.packetDurationMs,
            tsGapFilled: res.tsGapFilled,
            durationSec: round1(res.durationMs) / 1000,
            wavBytes: res.wavBytes,
          });
        } else if (res.error) {
          const key = `${role}|${res.ssrc}`;
          if (!unsupportedSeen.has(key)) {
            unsupportedSeen.add(key);
            manifest.unsupported.push({
              role,
              ssrc: res.ssrc,
              codec: res.codec,
              reason: res.error,
            });
          }
        }
      }
    }
  }

  // 视频流（与音频相同的逐抓包逻辑）
  if (mediaTypes === 'video' || mediaTypes === 'all') {
    for (const [ssrcKey, info] of Object.entries(classified.video)) {
      const ssrc = Number(ssrcKey);
      if (opts.ssrcFilter && !opts.ssrcFilter.has(ssrc)) continue;
      const codecName = info?.codec ?? null;
      for (const role of roles) {
        const cap = captures[role];
        if (!cap || !(ssrc in cap.streams)) continue;
        const res = reconstructVideoRaw(cap.packets, ssrc, serverIp, role, codecName);
        if (res.success && res.h264Bytes) {
          // 尝试封 MP4（失败静默降级，只留裸流）
          const mp4Bytes = tryMuxH264ToMp4(res.nals);
          manifest.video.push({
            callId,
            role,
            direction: res.direction,
            ssrc: res.ssrc,
            codec: codecName || res.codec,
            pt: res.pt,
            totalPackets: res.totalPackets,
            nalUnits: res.nalUnits,
            fuaFragments: res.fuaFragments,
            durationSec: res.durationSec,
            h264Bytes: res.h264Bytes,
            mp4Bytes: mp4Bytes ?? undefined,
            mp4Available: mp4Bytes !== null,
            mp4Error: mp4Bytes === null ? 'MP4 封装失败（缺 SPS/PPS 或参数不支持），已降级为裸流' : null,
          });
        } else if (res.error) {
          const key = `${role}|${res.ssrc}`;
          if (!unsupportedSeen.has(key)) {
            unsupportedSeen.add(key);
            manifest.unsupported.push({
              role,
              ssrc: res.ssrc,
              codec: res.codec,
              reason: res.error,
            });
          }
        }
      }
    }
  }

  return manifest;
}

// ---------------- 媒体流「谁到谁」标注 ----------------
// 回放页每条媒体文件只有「呼入/呼出」（相对抓包点的收发方向），FS 端一次
// 列出多条流时无法分辨哪条属于主叫腿、哪条属于被叫腿。这里从流所属通话的
// SIP 信令识别主叫/被叫，结合每条流的实际收发 IP 生成标注。

// 兜底角色短名：无 SIP 信令可依时，抓包点自己的 IP（非服务器）用此称呼。
// FS 抓包里的其他 IP 无法区分坐席/终端，不命名，直接显示原始 IP
const PARTY_ROLE_NAMES: Record<string, string> = {
  seat: '被叫端（坐席）',
  terminal: '主叫端（终端）',
  fs: 'FS',
};

/** SIP From/To 头的可读称呼：'张三（1002）' / '1002' / 显示名。
 * 身份串按抓包原文展示，不做 base64 解码。话机自报的超长无空格单
 * token 没有可读性，不采用——端点由展示层以 IP 标注。 */
export function identLabel(ident: SipIdentLike | null | undefined): string {
  if (!ident) return '';
  const name = (ident.name || '').trim();
  const user = (ident.user || '').trim();
  let label: string;
  if (name && user && name !== user && !name.includes(user)) {
    label = `${name}（${user}）`;
  } else {
    label = name || user;
  }
  if (label.length > 20 && !label.includes(' ')) return '';
  return label;
}

/** SIP 身份的最小结构要求（SipAddr 结构兼容；CallParties 的 ident 字段
 * 形状由并行模块定义，这里按此结构读取） */
export interface SipIdentLike {
  name?: string;
  user?: string;
}

/** extract_call_parties 的返回结构（与并行模块的 CallParties 对齐：
 * callerIp / callerIdent / answererIp / answererIdent） */
export interface CallPartiesInfo {
  callerIp: string | null;
  callerIdent: SipIdentLike;
  answererIp: string | null;
  answererIdent: SipIdentLike;
}

const EMPTY_IDENT: SipIdentLike = {};

const isRequestMsg = (m: SipFlowItem) => m.kind === 'request';

/** 从一通通话的信令流程里识别主叫/被叫的 IP 与身份。
 * 判定口径与前端 SIP 阶梯图一致：
 * - 主叫 = 第一个非服务器侧发出的 INVITE 的源，身份取其 From 头；
 * - 被叫 = INVITE 事务 200 OK 的非服务器发送方，身份取呼向它的 INVITE
 *   的 To 头——响应回显请求的 From，不能用作被叫身份。
 * 信令缺失时对应项为 null / 空 dict。 */
export function extractCallParties(
  call: Pick<CallInfo, 'signaling'>,
  serverIp: string | null,
): CallPartiesInfo {
  const flow = call.signaling || [];
  let inv = flow.find((m) => m.method === 'INVITE' && m.src !== serverIp) || null;
  if (!inv) inv = flow.find(isRequestMsg) || null;
  if (!inv) inv = flow.length ? flow[0] : null;
  const callerIp = inv ? inv.src : null;
  const callerIdent: SipIdentLike = inv ? inv.from : EMPTY_IDENT;

  const ok =
    flow.find((m) => m.method === '200' && m.cseqMethod === 'INVITE' && m.src !== serverIp) ||
    null;
  let answererIp = ok ? ok.src : null;
  if (answererIp === null) {
    // 未接通的通话（CANCEL/486/480/487 收场）没有 INVITE 的 200 OK：被叫
    // 退而取信令里出现最多的非服务器对端（与前端阶梯图同口径）
    const peers = new Map<string, number>();
    for (const m of flow) {
      for (const ip of [m.src, m.dst]) {
        if (ip && ip !== serverIp && ip !== callerIp) {
          peers.set(ip, (peers.get(ip) ?? 0) + 1);
        }
      }
    }
    if (peers.size) {
      let best: string | null = null;
      let bestN = -1;
      for (const [ip, n] of peers) {
        if (n > bestN) {
          bestN = n;
          best = ip;
        }
      }
      answererIp = best;
    }
  }
  let answererIdent: SipIdentLike = EMPTY_IDENT;
  if (answererIp) {
    // 呼向被叫的 INVITE 的 To；抓不到时退回 200 OK 的 To（回显同一头）
    let invTo = flow.find((m) => m.method === 'INVITE' && m.dst === answererIp && identLabel(m.to));
    if (!invTo) invTo = flow.find((m) => m.dst === answererIp && identLabel(m.to));
    answererIdent = (invTo ? invTo.to : null) || (ok ? ok.to : null) || EMPTY_IDENT;
  }

  return { callerIp, callerIdent, answererIp, answererIdent };
}

function partyLabel(
  ip: string | null,
  parties: CallPartiesInfo | null,
  serverIp: string | null,
  roleNames: Record<string, string>,
): string {
  if (parties) {
    if (ip && ip === parties.callerIp) {
      const ident = identLabel(parties.callerIdent);
      return ident ? `主叫 ${ident}` : '主叫';
    }
    if (ip && ip === parties.answererIp) {
      const ident = identLabel(parties.answererIdent);
      return ident ? `被叫 ${ident}` : '被叫';
    }
  }
  if (serverIp && ip === serverIp) return 'FS';
  if (ip !== null && ip in roleNames) return roleNames[ip];
  return ip || '';
}

/** 通话拓扑行：主叫 ↔ FS ↔ 被叫（各端称呼 + IP），无信令时为 null */
function partyChain(
  parties: CallPartiesInfo | null,
  serverIp: string | null,
): PartyChain | null {
  if (!parties || !(parties.callerIp || parties.answererIp)) return null;
  const label = (ip: string | null) => partyLabel(ip, parties, serverIp, {});
  const caller = parties.callerIp
    ? { label: label(parties.callerIp), ip: parties.callerIp }
    : null;
  const answerer = parties.answererIp
    ? { label: label(parties.answererIp), ip: parties.answererIp }
    : null;
  return { caller, answerer, serverIp };
}

/** 给媒体清单里的每条流标注收发双方（谁到谁），就地修改并返回。
 * 每条媒体文件写入结构化 flow 与简短 label；同时在 manifest.parties
 * 汇总本批媒体涉及的通话拓扑（主叫 ↔ FS ↔ 被叫，含 IP）。 */
export function describeMediaParties(
  manifest: MediaManifest,
  captures: Record<string, Capture>,
  calls: CallInfo[],
  serverIp: string | null,
  filesInfo?: { role: string; ips?: string[] }[],
): MediaManifest {
  const roleNames: Record<string, string> = {};
  for (const fi of filesInfo || []) {
    if (fi.role === 'fs') continue;
    for (const ip of fi.ips || []) {
      if (ip !== serverIp && !(ip in roleNames)) {
        roleNames[ip] = PARTY_ROLE_NAMES[fi.role] ?? fi.role;
      }
    }
  }

  const callOfSsrc: Record<number, CallInfo> = {};
  for (const call of calls || []) {
    for (const ssrc of call.ssrcs || []) {
      if (!(ssrc in callOfSsrc)) callOfSsrc[ssrc] = call;
    }
  }

  const partiesByCall = new Map<string, CallPartiesInfo>();
  const partiesOf = (call: CallInfo | null): CallPartiesInfo | null => {
    if (!call) return null;
    const key = call.callId ?? '';
    if (!partiesByCall.has(key)) {
      partiesByCall.set(key, extractCallParties(call, serverIp));
    }
    return partiesByCall.get(key) as CallPartiesInfo;
  };

  const labelEntry = (
    entry: { ssrc: string; role: string; label?: string; flow?: MediaFlow },
  ) => {
    const ssrc = parseInt(entry.ssrc, 16);
    if (Number.isNaN(ssrc)) return;
    const streamMeta: StreamInfo | undefined = captures[entry.role]?.streams?.[ssrc];
    const portPairs = streamMeta?.portPairs || [];
    if (!portPairs.length) return;
    const parties = partiesOf(callOfSsrc[ssrc] ?? null);
    // 媒体包的真实流向就是 src → dst（呼入 = 对端 → 本抓包点，呼出反之）
    const srcIp = portPairs[0][0];
    const dstIp = portPairs[0][2];
    entry.flow = {
      from: {
        label: partyLabel(srcIp, parties, serverIp, roleNames),
        ip: srcIp,
      },
      to: {
        label: partyLabel(dstIp, parties, serverIp, roleNames),
        ip: dstIp,
      },
    };
    entry.label = `${entry.flow.from.label} → ${entry.flow.to.label}`;
  };

  for (const entry of manifest.audio) labelEntry(entry);
  for (const entry of manifest.video) labelEntry(entry);
  for (const entry of manifest.unsupported) labelEntry(entry);

  // 拓扑汇总：只覆盖实际出现在回放里的媒体对应的通话，按主被叫去重
  const chains: PartyChain[] = [];
  const seen = new Set<string>();
  for (const entries of [manifest.audio, manifest.video]) {
    for (const entry of entries) {
      const ssrc = parseInt(entry.ssrc, 16);
      if (Number.isNaN(ssrc)) continue;
      const chain = partyChain(partiesOf(callOfSsrc[ssrc] ?? null), serverIp);
      if (!chain) continue;
      const key = `${chain.caller?.ip ?? ''}|${chain.answerer?.ip ?? ''}`;
      if (!seen.has(key)) {
        seen.add(key);
        chains.push(chain);
      }
    }
  }
  manifest.parties = chains;
  return manifest;
}
