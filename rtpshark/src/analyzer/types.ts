// 共享类型定义 —— 与 Python 版 rtp-stream-analyzer 的数据结构一一对应
// 命名约定：Python dict 的 snake_case 键在 TS 中改为 camelCase

export type StreamKind = 'audio' | 'video' | 'unknown';

/** 流的一个 (src_ip, src_port, dst_ip, dst_port) 四元组 */
export type PortPair = [string, number, string, number];

export interface SipAddr {
  name: string;
  user: string;
  host: string;
}

export interface SdpCodecIdent {
  name: string;
  rate: number | null;
}

export interface SdpEndpoint {
  kind: string;
  addr: string;
  port: number;
}

export interface SdpInfo {
  audio: string[];
  video: string[];
  map: { audio: Record<string, string>; video: Record<string, string> };
  full: { audio: SdpCodecIdent[]; video: SdpCodecIdent[] };
  mapFull: {
    audio: Record<string, SdpCodecIdent>;
    video: Record<string, SdpCodecIdent>;
  };
  endpoints: SdpEndpoint[];
}

/** SIP 信令事件（仅对话相关方法 + 所有响应码） */
export interface SipEvent {
  time: number;
  method: string; // 请求方法，或响应状态码字符串（'200'）
  reason: string;
  callId: string;
  cseq: number | null;
  cseqMethod: string;
  from: SipAddr;
  to: SipAddr;
  sdp: SdpInfo;
  src: string;
  dst: string;
}

export interface RtcpReportBlock {
  ssrc: number;
  fractionLostPct: number;
  cumLost: number;
  extHighSeq: number;
  jitter: number;
  lsr: number;
  dlsr: number;
}

export interface RtcpEvent {
  kind: 'SR' | 'RR' | 'NACK' | 'PLI' | 'FIR';
  time: number;
  src: string;
  dst: string;
  ssrc: number;
  // SR 专有
  rtpTs?: number;
  pktCount?: number;
  octetCount?: number;
  ntpSec?: number;
  ntpFrac?: number;
  // RR 专有
  reports?: RtcpReportBlock[];
  // NACK/PLI/FIR 专有（被反馈的媒体流 SSRC）
  mediaSsrc?: number;
  packets?: number;
  requested?: number;
}

/** 单条 RTP 流的汇总信息（对应 Python streams[ssrc]） */
export interface StreamInfo {
  count: number;
  pt: number[];
  ips: [string, string][]; // (src_ip, dst_ip) 对
  portPairs: PortPair[];
  kind: StreamKind;
  codec: string | null;
  clock: number | null;
}

/** 单个 RTP 包记录（按 (ssrc, seq) 去重后的首现） */
export interface RtpPacketRec {
  time: number; // 抓包时间戳（秒，epoch）
  rtpTs: number; // RTP 时间戳
  pt: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payload?: Uint8Array; // includePayload=true 时存在（12 字节 RTP 头之后的数据）
}

/** packets: ssrc -> (seq -> 记录)，首现去重 */
export type PacketMap = Map<number, Map<number, RtpPacketRec>>;

export interface CaptureIntegrityResult {
  status: 'ok' | 'warn';
  notes: string[];
  allPackets: number;
  truncated: number;
  truncatedRtp: number;
  maxMissingBytes: number;
  fileCut: boolean;
  snaplen: number | null;
}

export interface Capture {
  packets: PacketMap;
  totalCount: number;
  ips: string[];
  ssrcs: number[];
  streams: Record<number, StreamInfo>;
  captureStart: number | null;
  captureEnd: number | null;
  sipEvents: SipEvent[];
  rtcpEvents: RtcpEvent[];
  integrity: CaptureIntegrityResult;
}

/** getStreamPackets 返回的按时间排序的流内包 */
export interface StreamPacket {
  time: number;
  seq: number;
  rtpTs: number;
  pt: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  payload?: Uint8Array;
}

export type Role = string; // 'terminal' | 'seat' | 'fs' | 原始角色名

// ---------- 上传识别阶段（app.py /api/upload 的响应结构） ----------

export interface CallCompleteness {
  status: 'complete' | 'missing_start' | 'missing_end' | 'missing_both';
  reasons: string[];
}

export interface CallInfo {
  callId: string;
  ssrcs: number[];
  startTime: number;
  endTime: number;
  /** stream_count：通话内 SSRC 流条数 */
  streams: number;
  startStr: string;
  endStr: string;
  durationS: number;
  answerTime: number | null;
  byeTime: number | null;
  talkStartStr: string;
  talkEndStr: string;
  talkDurationS: number;
  files: string[];
  mediaTypes: string[];
  codecs: { audio: string[]; video: string[] };
  negotiatedCodecs: { audio: string[]; video: string[] };
  negotiatedPerLeg: Record<string, NegotiatedLeg>;
  fsMedia: FsMediaVerdict;
  sdpAnswered: boolean;
  isP2p: boolean;
  p2pEndpoints: string[];
  // 每份抓包 × 每通通话的完整性判断（Python assess_call_completeness 输出）
  integrity: {
    status: string;
    perFile: Record<string, { status: string; reasons: string[] }>;
  };
  // SIP 信令流程（阶梯图数据），按抓包优先级去重后
  signaling: SipFlowItem[];
  sipCallIds: string[];
  parties?: CallParties;
  fsRelay?: FsRelayVerdict | null;
  // 通话检出时附带的说明（各抓包中的出现情况等）
  notes?: string[];
}

export interface FileInfo {
  role: string;
  filename: string;
  totalPackets: number;
  ips: string[];
  streamCount: number;
  integrity: CaptureIntegrityResult;
}

export interface DirectionInfo {
  id: string;
  label: string;
  available: boolean;
  requires: string[];
}

export interface UploadResult {
  files: FileInfo[];
  serverIp: string | null;
  audioStreams: number;
  videoStreams: number;
  calls: CallInfo[];
  captureWarning: { roles: Record<string, unknown> } | null;
  integrityWarning: { files: { role: string; filename: string; notes: string[] }[] } | null;
  availableDirections: DirectionInfo[];
}

// ---------- 分析阶段（app.py /api/analyze 的结果结构） ----------

export interface RtcpStreamEntry {
  kind: 'audio' | 'video';
  sr?: Record<string, unknown>;
  rr?: Record<string, unknown>;
  fb?: Record<string, unknown>;
}

// 度量类结果的精确类型来自各移植模块
import type { InterPacketGapsResult } from './jitterAnalyzer';
import type { LabeledPacketLossResult } from './packetLoss';
import type { TsContinuityCheckResult } from './tsContinuity';
import type {
  ClockOffsetsResult,
  CrossCaptureDelayResult,
  DelaySummary,
  EndToEndDelayResult,
} from './delayAnalyzer';
import type {
  CallParties,
  FsMediaVerdict,
  FsRelayVerdict,
  NegotiatedLeg,
  SipFlowItem,
} from './callDetector';

export type GapResult = InterPacketGapsResult;
export type LossResult = LabeledPacketLossResult;
export type TsContinuityResult = TsContinuityCheckResult & { label: string };
export type CrossDelayResult = CrossCaptureDelayResult & { ssrc: number };
export type FsDelayResult = DelaySummary & { ssrcIn?: string; ssrcOut?: string };
export type ClockInfo = ClockOffsetsResult;

export interface AnalysisResults {
  direction: string;
  mediaType: string;
  checks: { delay: boolean; quality: boolean };
  callId: string | null;
  numCaptures: number;
  captureRoles: Record<string, string>;
  ipsInfo: Record<string, { ips: string[]; streamCount: number }>;
  detectedServerIp: string | null;
  streams: Record<number, StreamInfo>;
  classifiedStreams: ClassifiedStreams;
  captureIntegrity: Record<string, CaptureIntegrityResult>;
  jitter: Record<string, GapResult>;
  packetLoss: Record<number, LossResult>;
  tsContinuity: Record<string, TsContinuityResult>;
  rtcp: Record<string, RtcpStreamEntry>;
  audioHealth: AudioHealthResult;
  delayChains: DelayChainsResult;
  fsRelay?: FsRelayVerdict | null;
  mediaManifest: MediaManifest;
  audioQuality: Record<string, AudioQualityResult>;
  videoQuality: Record<string, VideoQualityResult>;
  fsDelay: FsDelayResult | null;
  crossDelays: CrossDelayResult[];
  clockInfo: ClockInfo;
  endToEnd?: EndToEndDelayResult;
  waterfall?: unknown[];
  report: Report;
}

export interface ClassifiedStreams {
  audio: Record<number, StreamInfo>;
  video: Record<number, StreamInfo>;
  unknown: Record<number, StreamInfo>;
}

// 跨模块结果类型采用宽松边界：精确接口由各移植模块自行定义并导出，
// 管道层（pipeline.ts）负责对接。此处仅在 AnalysisResults 中占位。
/* eslint-disable @typescript-eslint/no-explicit-any */
export type AudioHealthResult = any;
export type DelayChainsResult = any;
export type MediaManifest = any;
export type AudioQualityResult = any;
export type VideoQualityResult = any;
export type Report = any;
