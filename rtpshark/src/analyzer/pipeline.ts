// 分析管道 —— app.py /api/upload 与 /api/analyze 的 TS 移植。
// 在 Web Worker 里运行；角色 → 抓包数据全程在内存中。
import type {
  AnalysisResults,
  Capture,
  ClassifiedStreams,
  DirectionInfo,
  FileInfo,
  FsDelayResult,
  StreamInfo,
  StreamPacket,
  UploadResult,
} from './types';
import { extractRtpPackets } from './rtpParser';
import {
  classifyAllStreams,
  detectServerIp,
} from './streamClassifier';
import { mergeIntegrity } from './captureIntegrity';
import { detectCalls, checkCaptureConsistency } from './callDetector';
import {
  calcInterPacketGaps,
} from './jitterAnalyzer';
import { detectAllLosses } from './packetLoss';
import { checkTsContinuity } from './tsContinuity';
import {
  calcCrossCaptureDelay,
  calcFsInternalDelay,
  detectClockOffsets,
  estimateEndToEndDelay,
} from './delayAnalyzer';
import { buildDelayChains } from './delayChains';
import { summarizeRtcp } from './rtcpParser';
import { analyzeSilence, diagnoseAudio } from './silenceAnalyzer';
import type { SilenceProfile } from './silenceAnalyzer';
import {
  generateAllMedia,
  describeMediaParties,
} from './mediaExtractor';
import type { MediaManifest } from './mediaExtractor';
import {
  analyzeAudioQuality,
  analyzeVideoQuality,
} from './qualityAnalyzer';
import { generateReport } from './reporter';

export interface UploadFileInput {
  role: string;
  filename: string;
  bytes: Uint8Array;
}

export interface UploadSession {
  files: UploadFileInput[];
  filesInfo: FileInfo[];
  serverIp: string | null;
  captures: Record<string, Capture>; // 不含载荷，供上传识别
  allStreams: Record<number, StreamInfo>;
  classified: ClassifiedStreams;
  upload: UploadResult;
}

/** 上传阶段：解析各抓包 → 识别端点角色/服务器 IP/通话列表/完整性 */
export function uploadPhase(files: UploadFileInput[]): UploadSession {
  const filesInfo: FileInfo[] = [];
  const captures: Record<string, Capture> = {};
  const allStreams: Record<number, StreamInfo> = {};
  const allIps = new Set<string>();

  for (const f of files) {
    let cap: Capture;
    try {
      cap = extractRtpPackets(f.bytes, false);
    } catch {
      throw new Error(`文件 ${f.filename} 无法解析为抓包文件（格式不支持或已损坏）`);
    }
    captures[f.role] = cap;
    for (const [ssrc, info] of Object.entries(cap.streams)) {
      allStreams[Number(ssrc)] = info;
    }
    for (const ip of cap.ips) allIps.add(ip);
    filesInfo.push({
      role: f.role,
      filename: f.filename,
      totalPackets: cap.totalCount,
      ips: cap.ips
        .filter(
          (ip) =>
            !ip.startsWith('224.') &&
            !ip.startsWith('239.') &&
            ip !== '0.0.0.0' &&
            ip !== '255.255.255.255',
        )
        .sort(),
      streamCount: Object.keys(cap.streams).length,
      integrity: cap.integrity,
    });
  }

  const serverIp = detectServerIp(allStreams);
  const calls = detectCalls(captures, serverIp);

  const serverRoles = Object.entries(captures)
    .filter(([, cap]) => serverIp && cap.ips.includes(serverIp))
    .map(([role]) => role);

  const captureWarning = checkCaptureConsistency(calls, Object.keys(captures), {
    serverIp,
    serverRoles,
  });
  const integrityWarning = mergeIntegrity(filesInfo);
  const classified = classifyAllStreams(allStreams);
  const availableDirections = detectAvailableDirections(filesInfo, serverIp);

  return {
    files,
    filesInfo,
    serverIp,
    captures,
    allStreams,
    classified,
    upload: {
      files: filesInfo,
      serverIp,
      audioStreams: Object.keys(classified.audio).length,
      videoStreams: Object.keys(classified.video).length,
      calls,
      captureWarning: captureWarning as UploadResult['captureWarning'],
      integrityWarning,
      availableDirections,
    },
  };
}

function canonicalRole(role: string): string {
  const r = (role || '').trim().toLowerCase();
  if (r === 'fs') return 'fs';
  if (['seat', 'zuoxi', '坐席', '被叫'].includes(r)) return 'seat';
  if (['terminal', 'caller', '终端', '主叫'].includes(r)) return 'terminal';
  return role;
}

function detectAvailableDirections(
  filesInfo: FileInfo[],
  _serverIp: string | null,
): DirectionInfo[] {
  const roles = filesInfo.map((fi) => fi.role);
  const directions: DirectionInfo[] = [];
  const hasFs = roles.some((r) => r === 'fs' || r === 'FS');
  const hasSeat = ['seat', '坐席', 'zuoxi', '被叫'].some((r) => roles.includes(r));
  const hasTerminal = ['terminal', '终端', 'caller', '主叫'].some((r) => roles.includes(r));

  if (hasSeat && hasFs) {
    directions.push({
      id: 'seat_to_fs', label: '被叫 → FS 传输延迟', available: true,
      requires: ['被叫端（坐席）', 'FS端'],
    });
  }
  if (hasFs && hasTerminal) {
    directions.push({
      id: 'fs_to_terminal', label: 'FS → 主叫 传输延迟', available: true,
      requires: ['FS端', '主叫端（终端）'],
    });
  }
  if (hasSeat && hasFs && hasTerminal) {
    directions.push({
      id: 'seat_to_terminal', label: '被叫 → 主叫 端到端延迟', available: true,
      requires: ['被叫端（坐席）', 'FS端', '主叫端（终端）'],
    });
  }
  if (hasFs) {
    directions.push({
      id: 'fs_internal', label: 'FS 内部处理延迟', available: true,
      requires: ['FS端'],
    });
  }
  if (!directions.length) {
    directions.push({
      id: 'single_capture', label: '单端抖动/丢包分析', available: true,
      requires: ['任意一端'],
    });
  }
  return directions;
}

export interface AnalyzeParams {
  callId: string | null;
  mediaType: 'audio' | 'video' | 'all';
  direction: string;
  checkDelay: boolean;
}

export interface AnalyzeOutput {
  results: AnalysisResults;
  media: {
    callId: string | null;
    parties: unknown[];
    audio: MediaEntry[];
    video: MediaEntry[];
    unsupported: unknown[];
  };
}

export interface MediaEntry {
  key: string;
  role: string;
  ssrc: string;
  direction: string;
  label: string;
  durationSec?: number;
  wavBytes?: Uint8Array;
  mp4Bytes?: Uint8Array;
  h264Bytes?: Uint8Array;
}

const hexSsrc = (ssrc: number) => `0x${(ssrc >>> 0).toString(16).padStart(8, '0')}`;

/** 分析阶段：对齐 app.py run_analysis 的完整流程 */
export function analyzePhase(
  session: UploadSession,
  params: AnalyzeParams,
): AnalyzeOutput {
  const { serverIp, classified, filesInfo } = session;
  const calls = session.upload.calls || [];

  // 加载含载荷的抓包数据（供音视频重建/质量分析）
  const captures: Record<string, Capture> = {};
  for (const fi of filesInfo) {
    const f = session.files.find((x) => x.role === fi.role)!;
    const cap = extractRtpPackets(f.bytes, true);
    (cap as Capture & { _role: string })._role = canonicalRole(fi.role);
    captures[fi.role] = cap;
  }

  const mediaType = params.mediaType;
  let targetStreams: Record<number, StreamInfo> =
    mediaType === 'audio'
      ? classified.audio
      : mediaType === 'video'
        ? classified.video
        : { ...classified.audio, ...classified.video };

  // 通话过滤
  let selectedCall = params.callId
    ? calls.find((c) => c.callId === params.callId) ?? null
    : null;
  if (!params.callId && calls.length === 1) selectedCall = calls[0];

  const callSsrcs: Set<number> | null = selectedCall
    ? new Set(selectedCall.ssrcs)
    : null;
  if (callSsrcs) {
    targetStreams = Object.fromEntries(
      Object.entries(targetStreams).filter(([s]) => callSsrcs.has(Number(s))),
    );
  }

  const checkDelay = params.checkDelay;
  const results: AnalysisResults = {
    direction: params.direction,
    mediaType,
    checks: { delay: checkDelay, quality: true },
    callId: selectedCall ? selectedCall.callId : null,
    numCaptures: Object.keys(captures).length,
    captureRoles: Object.fromEntries(filesInfo.map((fi) => [fi.role, fi.filename])),
    ipsInfo: Object.fromEntries(
      filesInfo.map((fi) => [
        fi.role,
        { ips: fi.ips, streamCount: fi.streamCount },
      ]),
    ),
    detectedServerIp: serverIp,
    streams: session.allStreams,
    classifiedStreams: classified,
    captureIntegrity: Object.fromEntries(
      Object.entries(captures)
        .filter(([, cap]) => cap.integrity)
        .map(([role, cap]) => [role, cap.integrity]),
    ),
    jitter: {},
    packetLoss: {},
    tsContinuity: {},
    rtcp: {},
    audioHealth: {
      available: false,
      directions: [],
      summary: '未选中通话，无法按方向做无声诊断（请先选择通话）',
    },
    delayChains: {
      available: false,
      directions: [],
      roundtrip: [],
      notes: ['未选中通话，无法按方向定位链路延迟'],
    },
    mediaManifest: null,
    audioQuality: {},
    videoQuality: {},
    fsDelay: null,
    crossDelays: [],
    clockInfo: { offsets: {}, maxOffset: 0, warning: null },
    report: null,
  };

  // === 抖动分析 ===
  for (const [role, cap] of Object.entries(captures)) {
    for (const ssrc of Object.keys(targetStreams)) {
      const s = Number(ssrc);
      if (!cap.packets.has(s)) continue;
      const label = `${role} (SSRC=${hexSsrc(s)})`;
      const gap = calcInterPacketGaps(cap.packets, s);
      if (gap.count > 0) results.jitter[label] = gap;
    }
  }

  // === 丢包分析 ===
  for (const [role, cap] of Object.entries(captures)) {
    const ssrcs = Object.keys(targetStreams)
      .map(Number)
      .filter((s) => cap.packets.has(s));
    if (ssrcs.length) {
      const labels = Object.fromEntries(
        ssrcs.map((s) => [s, `${role} (SSRC=${hexSsrc(s)})`]),
      );
      Object.assign(results.packetLoss, detectAllLosses(cap.packets, ssrcs, labels));
    }
  }

  // === 时间戳连续性 ===
  for (const [role, cap] of Object.entries(captures)) {
    for (const ssrc of Object.keys(targetStreams)) {
      const s = Number(ssrc);
      if (!cap.packets.has(s)) continue;
      const label = `${role} (SSRC=${hexSsrc(s)})`;
      const kindInfo =
        classified.audio[s] || classified.video[s] || ({} as StreamInfo);
      const tsResult = checkTsContinuity(
        cap.packets,
        s,
        kindInfo.clock ?? null,
        kindInfo.kind ? kindInfo.kind === 'audio' : null,
      );
      if (tsResult.packetCount > 0) {
        results.tsContinuity[label] = { ...tsResult, label };
      }
    }
  }

  // === RTCP 汇总 + 无声诊断 + 分段延迟链路 ===
  const canonCaptures: Record<string, Capture> = {};
  for (const cap of Object.values(captures)) {
    canonCaptures[(cap as Capture & { _role: string })._role] = cap;
  }

  const rtcpByRole: Record<string, ReturnType<typeof summarizeRtcp>> = {};
  for (const [role, cap] of Object.entries(canonCaptures)) {
    rtcpByRole[role] = summarizeRtcp(cap);
  }
  const silenceProfiles: Record<string, SilenceProfile> = {};
  for (const [role, cap] of Object.entries(canonCaptures)) {
    const summ = rtcpByRole[role];
    for (const ssrc of Object.keys(targetStreams)) {
      const s = Number(ssrc);
      const info = cap.streams[s];
      if (!info) continue;
      const isAudio = s in classified.audio;
      const isVideo = s in classified.video;
      if (!isAudio && !isVideo) continue;
      if (isAudio) silenceProfiles[`${role}:${s}`] = analyzeSilence(cap.packets, s);
      const entry: Record<string, unknown> = {
        kind: isAudio ? 'audio' : 'video',
      };
      if (summ.sr[s]) entry.sr = summ.sr[s];
      if (summ.rr[s]) entry.rr = summ.rr[s];
      if (summ.fb?.[s]) entry.fb = summ.fb[s];
      results.rtcp[`${role} (SSRC=${hexSsrc(s)})`] =
        entry as unknown as AnalysisResults['rtcp'][string];
    }
  }

  if (selectedCall) {
    const parties = mod.extractCallParties(selectedCall, serverIp);
    results.audioHealth = diagnoseAudio(
      canonCaptures,
      selectedCall,
      serverIp,
      silenceProfiles,
      rtcpByRole,
      parties,
    );
    results.delayChains = checkDelay
      ? buildDelayChains(canonCaptures, selectedCall, serverIp, parties)
      : {
          available: false,
          directions: [],
          roundtrip: [],
          notes: ['未勾选延迟分析，跳过分段延迟链路测量'],
        };
    results.fsRelay = selectedCall.fsRelay ?? null;
  } else {
    results.delayChains = {
      available: false,
      directions: [],
      roundtrip: [],
      notes: ['未选中通话，无法按方向定位链路延迟'],
    };
  }

  // === 音视频重建（内存中） ===
  const mediaManifest = generateAllMedia(
    captures,
    classified,
    serverIp,
    mediaType === 'audio' || mediaType === 'video' ? mediaType : 'all',
    { ssrcFilter: callSsrcs ?? undefined, callId: selectedCall?.callId ?? null },
  );
  describeMediaParties(mediaManifest, captures, calls, serverIp, filesInfo);
  results.mediaManifest = mediaManifest;

  // === 音画质量分析 ===
  for (const [role, cap] of Object.entries(captures)) {
    for (const ssrc of Object.keys(targetStreams)) {
      const s = Number(ssrc);
      if (!cap.streams[s]) continue;
      const label = `${role} (SSRC=${hexSsrc(s)})`;
      if (s in classified.audio) {
        results.audioQuality[label] =
          analyzeAudioQuality(cap.packets, s) as AnalysisResults['audioQuality'][string];
      } else if (s in classified.video) {
        results.videoQuality[label] =
          analyzeVideoQuality(cap.packets, s) as AnalysisResults['videoQuality'][string];
      }
    }
  }

  // === FS 内部延迟 ===
  const fsRole = Object.keys(captures).find((r) => r.toLowerCase() === 'fs');
  if (checkDelay && fsRole) {
    results.fsDelay = findAndCalcFsDelay(captures[fsRole].packets, targetStreams, serverIp);
  }

  // === 跨抓包延迟 ===
  if (checkDelay && Object.keys(captures).length >= 2) {
    const roles = Object.keys(captures);
    for (let i = 0; i < roles.length; i++) {
      for (let j = i + 1; j < roles.length; j++) {
        for (const ssrc of Object.keys(targetStreams)) {
          const s = Number(ssrc);
          if (
            captures[roles[i]].packets.has(s) &&
            captures[roles[j]].packets.has(s)
          ) {
            const cd = calcCrossCaptureDelay(
              captures[roles[i]].packets,
              captures[roles[j]].packets,
              s,
              roles[i],
              roles[j],
            );
            if (cd.count > 0) results.crossDelays.push({ ...cd, ssrc: s });
          }
        }
      }
    }
  }

  // === 时钟偏移 ===
  results.clockInfo = detectClockOffsets(results.crossDelays);

  // === 端到端延迟 ===
  if (results.fsDelay && (results.fsDelay as { count?: number }).count) {
    results.endToEnd = estimateEndToEndDelay(results.fsDelay);
  }

  // === 报告 ===
  results.report = generateReport({
    ...results,
    fsDelay: results.fsDelay
      ? {
          ...results.fsDelay,
          outliers50ms: results.fsDelay.outliers50Ms,
          outliers100ms: results.fsDelay.outliers100Ms,
        }
      : null,
    classifiedStreams: {
      audio: adaptClassified(classified.audio),
      video: adaptClassified(classified.video),
      unknown: adaptClassified(classified.unknown),
    },
  });

  // === 汇总媒体条目（供 UI 生成 Blob 播放） ===
  const media = {
    callId: mediaManifest?.callId ?? null,
    parties: mediaManifest?.parties ?? [],
    audio: extractMediaEntries(mediaManifest, 'audio'),
    video: extractMediaEntries(mediaManifest, 'video'),
    unsupported: mediaManifest?.unsupported ?? [],
  };

  return { results, media };
}

/** reporter 消费的流分类形态（ClassifiedStreamInfo）：ips 保留 (src, dst) 元组 */
function adaptClassified(
  bucket: Record<number, StreamInfo>,
): Record<string, { pt: number[]; count: number; ips: [string, string][] }> {
  return Object.fromEntries(
    Object.entries(bucket).map(([ssrc, info]) => [
      ssrc,
      { pt: info.pt, count: info.count, ips: info.ips },
    ]),
  );
}

function extractMediaEntries(
  manifest: MediaManifest,
  kind: 'audio' | 'video',
): MediaEntry[] {
  const list = (manifest?.[kind] || []) as unknown as Record<string, unknown>[];
  return list.map((e, i) => ({
    key: `${e.role}_${e.ssrc}_${i}`,
    role: String(e.role ?? ''),
    ssrc: String(e.ssrc ?? ''),
    direction: String(e.direction ?? ''),
    label: String(e.label ?? e.role ?? ''),
    durationSec: e.durationSec as number | undefined,
    wavBytes: e.wavBytes as Uint8Array | undefined,
    mp4Bytes: e.mp4Bytes as Uint8Array | undefined,
    h264Bytes: e.h264Bytes as Uint8Array | undefined,
  }));
}

import * as mod from './callDetector';

// ---------- FS 内部延迟（app.py _find_and_calc_fs_delay） ----------
import { getStreamPackets } from './rtpParser';
import type { PacketMap } from './types';

function hasSsrc(packets: PacketMap, ssrc: number): boolean {
  return packets.has(ssrc);
}

function findAndCalcFsDelay(
  fsPackets: PacketMap,
  targetStreams: Record<number, StreamInfo>,
  serverIp: string | null,
): FsDelayResult | null {
  const inbound: Record<number, StreamPacket[]> = {};
  const outbound: Record<number, StreamPacket[]> = {};

  for (const ssrc of Object.keys(targetStreams).map(Number)) {
    if (!hasSsrc(fsPackets, ssrc)) continue;
    const pkts = getStreamPackets(fsPackets, ssrc);
    if (!pkts.length) continue;
    const dstIp = pkts[0].dstIp;
    if (serverIp && dstIp === serverIp) inbound[ssrc] = pkts;
    else if (serverIp && pkts[0].srcIp === serverIp) outbound[ssrc] = pkts;
  }

  if (!Object.keys(inbound).length || !Object.keys(outbound).length) {
    const portPairs: Record<number, [string, number, string, number]> = {};
    for (const ssrc of Object.keys(targetStreams).map(Number)) {
      if (!hasSsrc(fsPackets, ssrc)) continue;
      const pkts = getStreamPackets(fsPackets, ssrc);
      if (pkts.length) {
        portPairs[ssrc] = [
          pkts[0].srcIp, pkts[0].srcPort, pkts[0].dstIp, pkts[0].dstPort,
        ];
      }
    }
    for (const [a, pa] of Object.entries(portPairs)) {
      for (const [b, pb] of Object.entries(portPairs)) {
        if (a !== b && pa[0] === pb[2] && pa[1] === pb[3] && pa[2] === pb[0] && pa[3] === pb[1]) {
          inbound[Number(a)] = getStreamPackets(fsPackets, Number(a));
          outbound[Number(b)] = getStreamPackets(fsPackets, Number(b));
        }
      }
    }
  }

  let best: FsDelayResult | null = null;
  for (const sIn of Object.keys(inbound).map(Number)) {
    for (const sOut of Object.keys(outbound).map(Number)) {
      if (sIn === sOut) continue;
      const result = calcFsInternalDelay(fsPackets, sIn, sOut);
      if (result.count > 0) {
        if (best === null || result.count > best.count) {
          best = { ...result, ssrcIn: hexSsrc(sIn), ssrcOut: hexSsrc(sOut) };
        }
      }
    }
  }
  return best;
}
