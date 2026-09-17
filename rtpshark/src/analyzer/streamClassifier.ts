// RTP 流分类器（stream_classifier.py 的 TS 移植）
import type { PortPair, StreamInfo, StreamKind } from './types';

export const AUDIO_PT = new Set([0, 3, 8, 9, 18]); // PCMU, GSM, PCMA, G722, G729
export const VIDEO_PT_RANGE = (pt: number) => pt >= 96 && pt <= 127;

// 实测时钟率区间（8k / 48k 视为音频，90k 视为视频）
const AUDIO_CLOCK_EST: [number, number, number, number] = [7200, 8800, 43000, 53000];
const VIDEO_CLOCK_EST: [number, number] = [81000, 99000];

export const PT_NAMES: Record<number, string> = {
  0: 'PCMU (G.711 μ-law)',
  3: 'GSM',
  8: 'PCMA (G.711 A-law)',
  9: 'G722',
  18: 'G729',
};

export const AUDIO_CLOCK_RATE = 8000;
export const VIDEO_CLOCK_RATE = 90000;

export interface SdpPtMaps {
  audio: Record<string, { name: string; rate: number | null }>;
  video: Record<string, { name: string; rate: number | null }>;
}

/** 判定一条流是音频还是视频，返回 [kind, codec, clock] */
export function resolveStreamKind(
  portPairs: PortPair[],
  pts: number[],
  estClock: number | null,
  portKinds: Record<string, 'audio' | 'video'> | null,
  ptMaps: SdpPtMaps | null,
): [StreamKind, string | null, number | null] {
  let kind: StreamKind | null = null;
  let codec: string | null = null;
  let clock: number | null = null;
  const sorted = [...pts].sort((a, b) => a - b);
  const mainPt = sorted.length ? sorted[0] : null;

  // 1. SDP 端口绑定
  if (portKinds && portPairs.length) {
    const hits = { audio: 0, video: 0 };
    for (const pp of portPairs) {
      for (const [ip, port] of [
        [pp[0], pp[1]],
        [pp[2], pp[3]],
      ]) {
        const k = portKinds[`${ip}:${port}`];
        if (k) hits[k] += 1;
      }
    }
    if (hits.audio && !hits.video) kind = 'audio';
    else if (hits.video && !hits.audio) kind = 'video';
  }

  // 2. rtpmap 单侧命中
  if (kind === null && ptMaps && mainPt !== null) {
    const inAudio = mainPt in (ptMaps.audio || {});
    const inVideo = mainPt in (ptMaps.video || {});
    if (inAudio && !inVideo) kind = 'audio';
    else if (inVideo && !inAudio) kind = 'video';
  }

  // 3. 实测时钟率
  if (kind === null && estClock) {
    const [lo8, hi8, lo48, hi48] = AUDIO_CLOCK_EST;
    const [vlo, vhi] = VIDEO_CLOCK_EST;
    if ((estClock >= lo48 && estClock <= hi48) || (estClock >= lo8 && estClock <= hi8)) {
      kind = 'audio';
    } else if (estClock >= vlo && estClock <= vhi) {
      kind = 'video';
    }
  }

  // 4. 静态 PT 表兜底
  if (kind === null && mainPt !== null) {
    if (AUDIO_PT.has(mainPt)) kind = 'audio';
    else if (VIDEO_PT_RANGE(mainPt)) kind = 'video';
  }

  if (kind === 'audio') {
    const entry = mainPt !== null ? (ptMaps?.audio || {})[mainPt] : undefined;
    codec = entry?.name || (mainPt !== null ? PT_NAMES[mainPt] : undefined) || null;
    clock =
      entry?.rate ||
      (codec && codec.toUpperCase().startsWith('OPUS') ? 48000 : AUDIO_CLOCK_RATE);
  } else if (kind === 'video') {
    const entry = mainPt !== null ? (ptMaps?.video || {})[mainPt] : undefined;
    codec = entry?.name || null;
    clock = entry?.rate || VIDEO_CLOCK_RATE;
  }
  return [kind ?? 'unknown', codec, clock];
}

export function classifyStream(info: Partial<StreamInfo>): StreamKind {
  const pts = info.pt || [];
  if (!pts.length) return 'unknown';
  for (const pt of pts) if (AUDIO_PT.has(pt)) return 'audio';
  for (const pt of pts) if (VIDEO_PT_RANGE(pt)) return 'video';
  return 'unknown';
}

export function classifyAllStreams(
  streams: Record<number, StreamInfo>,
): { audio: Record<number, StreamInfo>; video: Record<number, StreamInfo>; unknown: Record<number, StreamInfo> } {
  const result = { audio: {}, video: {}, unknown: {} } as Record<StreamKind, Record<number, StreamInfo>>;
  for (const [k, info] of Object.entries(streams)) {
    const ssrc = Number(k);
    const kind = info.kind || classifyStream(info);
    (result[kind] ?? result.unknown)[ssrc] = info;
  }
  return result;
}

export function getClockRate(pt: number): number | null {
  if (AUDIO_PT.has(pt)) return AUDIO_CLOCK_RATE;
  if (VIDEO_PT_RANGE(pt)) return VIDEO_CLOCK_RATE;
  return null;
}

export function getPtName(pt: number): string {
  if (PT_NAMES[pt]) return PT_NAMES[pt];
  if (VIDEO_PT_RANGE(pt)) return `Dynamic (Video, PT=${pt})`;
  return `Unknown (PT=${pt})`;
}

export function identifyDirection(
  info: Partial<StreamInfo>,
  serverIp: string | null,
): 'inbound' | 'outbound' | 'unknown' {
  const portPairs = info.portPairs || [];
  if (!portPairs.length || !serverIp) return 'unknown';
  for (const pp of portPairs) {
    if (pp[2] === serverIp) return 'inbound';
    if (pp[0] === serverIp) return 'outbound';
  }
  return 'unknown';
}

/** 自动检测服务器 IP（RTP 收发连接数最多的 IP） */
export function detectServerIp(
  allStreams: Record<number, StreamInfo>,
): string | null {
  const ipConnections: Record<string, number> = {};
  for (const info of Object.values(allStreams)) {
    for (const pp of info.portPairs || []) {
      ipConnections[pp[0]] = (ipConnections[pp[0]] || 0) + 1;
      ipConnections[pp[2]] = (ipConnections[pp[2]] || 0) + 1;
    }
  }
  const keys = Object.keys(ipConnections);
  if (!keys.length) return null;
  return keys.reduce((a, b) => (ipConnections[a] >= ipConnections[b] ? a : b));
}

/** 在一份抓包里按收发 IP 条件选通话音频流（多个命中取包数最多的） */
export function pickCallStream(
  cap: { streams: Record<number, StreamInfo> },
  callSsrcs: number[],
  srcIs: string | null = null,
  dstIs: string | null = null,
): number | null {
  let best: number | null = null;
  let bestN = 0;
  for (const ssrc of callSsrcs) {
    const info = cap.streams?.[ssrc];
    if (!info) continue;
    if (info.kind !== 'audio' && !info.pt.some((pt) => AUDIO_PT.has(pt))) continue;
    for (const pp of info.portPairs || []) {
      if (srcIs && pp[0] !== srcIs) continue;
      if (dstIs && pp[2] !== dstIs) continue;
      if (info.count > bestN) {
        best = ssrc;
        bestN = info.count;
      }
      break;
    }
  }
  return best;
}
