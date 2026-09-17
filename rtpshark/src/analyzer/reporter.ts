// 报告生成器 —— 移植自 Python analyzer/reporter.py，并内联移植其依赖的
// analyzer/problem_taxonomy.py（声音问题分类）与 analyzer/video_problem_taxonomy.py
// （视频问题分类）。阈值 / 分级 / 中文文案与 Python 版逐字对应。
//
// 输入接口 ReportInput 按 Python 版实际访问的键声明为最小结构（camelCase），
// 由管道层与真实分析模块对接；输出 Report 结构对照 Python 报告 dict。
import type { EndToEndDelayResult } from './delayAnalyzer';

// ==================== 输入接口（分析结果的被消费键） ====================

/** 键控记录：同时兼容字符串键与数字键（SSRC）两种上游形态 */
export type KeyedRecord<T> = Record<string, T> | Record<number, T>;

/** 单条 RTP 流在分类桶里的最小信息 */
export interface ClassifiedStreamInfo {
  pt?: number[];
  count?: number;
  /** (src_ip, dst_ip) 对列表 */
  ips?: [string, string][];
}

/** classified_streams 的三个分桶 */
export interface ReportClassifiedStreams {
  audio?: KeyedRecord<ClassifiedStreamInfo> | null;
  video?: KeyedRecord<ClassifiedStreamInfo> | null;
  unknown?: KeyedRecord<ClassifiedStreamInfo> | null;
}

/** FS 内部延迟统计（reporter 只消费统计字段） */
export interface FsDelayStatsInput {
  mean?: number;
  p50?: number;
  p95?: number;
  p99?: number;
  max?: number;
  std?: number;
  count?: number;
  /** Python outliers_50ms 的两种 camel 拼写（reporter / delayAnalyzer） */
  outliers50ms?: number;
  outliers100ms?: number;
  outliers50Ms?: number;
  outliers100Ms?: number;
}

/** 取 >50ms 尖峰计数（兼容两种拼写） */
function outliers50(d: FsDelayStatsInput): number {
  return d.outliers50Ms ?? d.outliers50ms ?? 0;
}

/** 取 >100ms 尖峰计数（兼容两种拼写） */
function outliers100(d: FsDelayStatsInput): number {
  return d.outliers100Ms ?? d.outliers100ms ?? 0;
}

/** 跨抓包延迟条目 */
export interface CrossDelayInput {
  label?: string;
  mean?: number;
  p95?: number;
  clockOffsetMs?: number;
}

/** 单条流的抖动统计 */
export interface JitterStatInput {
  mean?: number;
  median?: number;
  std?: number;
  p95?: number;
  abnormalCount?: number;
  expectedInterval?: number;
}

/** 单条流的丢包统计 */
export interface PacketLossStatInput {
  label?: string;
  totalPackets?: number;
  totalLost?: number;
  lossRatePct?: number;
  reorderCount?: number;
  isClean?: boolean;
}

/** 时间戳连续性事件明细 */
export interface TsEventInput {
  time: number;
  kind: string;
  seq: number;
  ts?: number | null;
  prevSeq?: number | null;
  prevTs?: number | null;
  tsDelta: number;
  mediaGapMs?: number | null;
  arrivalGapMs?: number | null;
}

/** 单条流的时间戳连续性统计 */
export interface TsContinuityStatInput {
  isContinuous?: boolean;
  packetCount?: number;
  pt?: number | null;
  clockRate?: number | null;
  mode?: string | null;
  packetDurationMs?: number | null;
  eventCount?: number;
  jumpCount?: number;
  backwardCount?: number;
  reorderCount?: number;
  duplicateCount?: number;
  wrapCount?: number;
  totalMediaGapMs?: number;
  medianTsDelta?: number | null;
  events?: TsEventInput[] | null;
}

/** 时钟偏移信息 */
export interface ClockInfoInput {
  offsets?: Record<string, unknown> | null;
  maxOffset?: number;
  warning?: string | null;
}

/** 无声诊断的单方向判定 */
export interface AudioHealthDirectionInput {
  verdict?: string;
  label?: string;
  verdictText?: string;
}

/** 无声诊断结果 */
export interface AudioHealthInput {
  available?: boolean;
  directions?: AudioHealthDirectionInput[] | null;
}

/** 分段延迟链路的单方向判定 */
export interface DelayChainDirectionInput {
  verdict?: string;
  label?: string;
  verdictText?: string;
}

/** 分段延迟链路的往返条目 */
export interface DelayChainRoundtripInput {
  status?: string;
  pair?: string;
  ms?: number;
}

/** 分段延迟链路结果 */
export interface DelayChainsInput {
  available?: boolean;
  directions?: DelayChainDirectionInput[] | null;
  roundtrip?: DelayChainRoundtripInput[] | null;
}

/** FS 媒体转发的单设备上/下行计数 */
export interface FsRelayDeviceTraffic {
  pkts: number;
}

/** FS 媒体转发的单设备条目 */
export interface FsRelayDeviceInput {
  ip: string;
  label: string;
  uplink: { audio: FsRelayDeviceTraffic; video: FsRelayDeviceTraffic };
  downlink: { audio: FsRelayDeviceTraffic; video: FsRelayDeviceTraffic };
}

/** FS 媒体转发判定结果 */
export interface FsRelayInput {
  available?: boolean;
  verdict?: string;
  headline?: string;
  notes?: string[] | null;
  devices?: FsRelayDeviceInput[] | null;
}

/** RTCP RR 报告块的最小消费字段 */
export interface RtcpRrInput {
  fractionLostPct?: number;
  cumLost?: number;
}

/** RTCP 反馈（NACK/PLI/FIR）的最小消费字段 */
export interface RtcpFbInput {
  nack?: { requested?: number; packets?: number } | null;
  pli?: { count?: number } | null;
  fir?: { count?: number } | null;
}

/** 单条流的 RTCP 条目 */
export interface RtcpEntryInput {
  kind?: string;
  rr?: RtcpRrInput | null;
  fb?: RtcpFbInput | null;
}

/** 音画质量检测的 issue */
export interface QualityIssueInput {
  kind?: string;
  severity?: string;
  message?: string;
}

/** RTP 秩序（时间戳倒退/重复）最小消费字段 */
export interface QualityRtpIntegrityInput {
  tsBackward?: number;
  tsDuplicate?: number;
}

/** 音/视频质量检测结果条目 */
export interface QualityEntryInput {
  issues?: QualityIssueInput[] | null;
  verdict?: string;
  rtpIntegrity?: QualityRtpIntegrityInput | null;
  decodable?: boolean;
  codec?: string;
}

/** 抓包完整性（截短/文件尾损坏）条目 */
export interface CaptureIntegrityInput {
  status?: string;
  notes?: string[] | null;
}

/**
 * generateReport 的输入：Python 版 generate_report(analysis_results) 访问的
 * 全部键的最小结构（camelCase）。所有键均可缺省，缺省行为与 Python 的
 * dict.get 默认值一致。
 */
export interface ReportInput {
  mediaType?: string;
  direction?: string;
  numCaptures?: number;
  captureRoles?: Record<string, string>;
  ipsInfo?: Record<string, { ips?: string[]; streamCount?: number }>;
  detectedServerIp?: string | null;
  classifiedStreams?: ReportClassifiedStreams | null;
  fsDelay?: FsDelayStatsInput | null;
  crossDelays?: CrossDelayInput[] | null;
  /** 端到端延迟结果（Python 原样透传给前端的区块） */
  endToEnd?: EndToEndDelayResult | null;
  jitter?: Record<string, JitterStatInput> | null;
  packetLoss?: KeyedRecord<PacketLossStatInput> | null;
  tsContinuity?: Record<string, TsContinuityStatInput> | null;
  clockInfo?: ClockInfoInput | null;
  audioHealth?: AudioHealthInput | null;
  delayChains?: DelayChainsInput | null;
  fsRelay?: FsRelayInput | null;
  rtcp?: Record<string, RtcpEntryInput> | null;
  audioQuality?: Record<string, QualityEntryInput> | null;
  videoQuality?: Record<string, QualityEntryInput> | null;
  captureIntegrity?: Record<string, CaptureIntegrityInput> | null;
  checks?: { delay?: boolean; quality?: boolean } | null;
}

// ==================== 输出接口（对照 Python 报告 dict） ====================

export type IssueSeverity = 'critical' | 'warning' | 'info';

/** 结论里的一条问题（时间戳类问题额外带 stream 与 explain） */
export interface ReportIssue {
  severity: IssueSeverity;
  message: string;
  stream?: string;
  explain?: string;
}

export interface ReportConclusion {
  issues: ReportIssue[];
  okItems: string[];
  rootCause: string;
  overall: 'healthy' | 'warning' | 'critical';
}

export interface ReportMetadata {
  generatedAt: string;
  direction: string;
  mediaType: string;
  numCaptures: number;
  captureRoles: Record<string, string>;
}

export interface ReportTopologyEndpoint {
  role: string;
  ip: string;
  streamCount: number;
}

export interface ReportTopology {
  endpoints: ReportTopologyEndpoint[];
  server: string | null;
  connections: unknown[];
}

export interface ReportStreamEntry {
  ssrc: string;
  pt: number[];
  packetCount: number;
  ips: [string, string][];
}

export interface ReportStreamSummary {
  totalAudio: number;
  totalVideo: number;
  totalUnknown: number;
  audioStreams: ReportStreamEntry[];
  videoStreams: ReportStreamEntry[];
}

export interface ReportFsDelayInternal {
  mean: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  std: number;
  count: number;
  outliers50ms: number;
  outliers100ms: number;
  available: boolean;
}

export interface ReportCrossDelay {
  label: string;
  mean: number;
  p95: number;
  clockOffsetMs: number;
}

export interface ReportDelaySummary {
  fsInternal: ReportFsDelayInternal;
  crossCapture: ReportCrossDelay[];
  endToEnd?: EndToEndDelayResult | null;
}

export interface ReportJitterEntry {
  mean: number;
  median: number;
  std: number;
  p95: number;
  abnormalCount: number;
  expectedInterval: number;
}

export interface ReportLossEntry {
  label: string;
  totalPackets: number;
  totalLost: number;
  lossRatePct: number;
  reorderCount: number;
  isClean: boolean;
}

export interface ReportTsEvent {
  timeStr: string;
  kind: string;
  seq: number;
  ts: number | null;
  prevSeq: number | null;
  prevTs: number | null;
  tsDelta: number;
  mediaGapMs: number | null;
  arrivalGapMs: number | null;
}

export interface ReportTsStream {
  isContinuous: boolean;
  packetCount: number;
  pt: number | null;
  clockRate: number | null;
  mode: string | null;
  packetDurationMs: number | null;
  eventCount: number;
  jumpCount: number;
  backwardCount: number;
  reorderCount: number;
  duplicateCount: number;
  wrapCount: number;
  totalMediaGapMs: number;
  events: ReportTsEvent[];
}

export interface ReportTsContinuity {
  streams: Record<string, ReportTsStream>;
}

export interface ReportClockOffset {
  offsets: Record<string, unknown>;
  maxOffsetMs: number;
  warning: string | null;
}

export interface ReportMediaQuality {
  audio: Record<string, QualityEntryInput>;
  video: Record<string, QualityEntryInput>;
}

/** 问题分类的单条问题条目 */
export interface ProblemEntry {
  id: string;
  name: string;
  category: string;
  term: string;
  priority: string;
  severity: IssueSeverity;
  feel: string[];
  description: string;
  evidence: string[];
  sources: string[];
  causes: string[];
  verify: string[];
}

/** 抓包看不到的听感/观感问题（只给人工验证方法） */
export interface UnobservableItem {
  name: string;
  category: string;
  feel: string[];
  why: string;
  verify: string;
}

/** 声音/视频问题分类报告（classify_problems / classify_video_problems 输出） */
export interface ProblemClassification {
  available: boolean;
  problems: ProblemEntry[];
  unobservable: UnobservableItem[];
  summary: string;
  notes: string[];
}

/** 完整分析报告（结构对照 Python generate_report 的返回 dict） */
export interface Report {
  metadata: ReportMetadata;
  topology: ReportTopology;
  streams: ReportStreamSummary;
  delay: ReportDelaySummary;
  jitter: Record<string, ReportJitterEntry>;
  packetLoss: Record<string, ReportLossEntry>;
  timestampContinuity: ReportTsContinuity;
  clockOffset: ReportClockOffset;
  audioHealth: AudioHealthInput | null;
  delayChains: DelayChainsInput | null;
  rtcp: Record<string, RtcpEntryInput> | null;
  mediaQuality: ReportMediaQuality;
  conclusion: ReportConclusion;
  /** 仅 mediaType 为 audio/all 时存在（声音问题分类） */
  problemClassification?: ProblemClassification;
  /** 仅 mediaType 为 video/all 时存在（视频问题分类） */
  videoProblemClassification?: ProblemClassification;
}

// ==================== 通用工具 ====================

/** 抓包文件角色 → 展示名（issue 文案用；stream 键仍保留原始 label） */
export const ROLE_LABELS: Record<string, string> = {
  fs: 'FS 服务器端',
  FS: 'FS 服务器端',
  seat: '被叫端（坐席）',
  坐席: '被叫端（坐席）',
  zuoxi: '被叫端（坐席）',
  被叫: '被叫端（坐席）',
  terminal: '主叫端（终端）',
  终端: '主叫端（终端）',
  caller: '主叫端（终端）',
  主叫: '主叫端（终端）',
};

/** 把 "role (SSRC=0x…)" 的角色前缀换成中文展示名。 */
function prettyLabel(label: string): string {
  const idx = label.indexOf(' (');
  if (idx < 0) return label;
  const role = label.slice(0, idx);
  const rest = label.slice(idx + 2);
  return `${ROLE_LABELS[role] ?? role} (${rest}`;
}

/** 把累计媒体时间缺口换成人类可读的单位。 */
export function gapHuman(gapMs: number): string {
  if (gapMs >= 60000) return `${(gapMs / 60000).toFixed(1)} 分钟`;
  if (gapMs >= 1000) return `${(gapMs / 1000).toFixed(1)} 秒`;
  return `${gapMs.toFixed(0)} 毫秒`;
}

/** epoch 秒 → 本地 HH:MM:SS（对照 Python datetime.strftime('%H:%M:%S')） */
function fmtTimeOfDay(t: number): string {
  const d = new Date(t * 1000);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const SEVERITY_VALUES: readonly IssueSeverity[] = ['critical', 'warning', 'info'];

function asSeverity(v: string | undefined, fallback: IssueSeverity): IssueSeverity {
  return SEVERITY_VALUES.includes(v as IssueSeverity) ? (v as IssueSeverity) : fallback;
}

function f1(v: number | undefined): string {
  return (v ?? 0).toFixed(1);
}

function f2(v: number | undefined): string {
  return (v ?? 0).toFixed(2);
}

/** 结果字典键（int SSRC / '0x…' 串 / '…(SSRC=0x…)' 标签）→ SSRC 整数 */
function ssrcIntOf(key: number | string): number | null {
  if (typeof key === 'number') return key;
  const m = /0x([0-9a-fA-F]+)/.exec(String(key));
  return m ? parseInt(m[1], 16) : null;
}

/** 判定一个结果键（SSRC）属于 audio 还是 video（对照 problem_taxonomy.stream_media_kind） */
export function streamMediaKind(results: ReportInput, key: number | string): 'audio' | 'video' {
  const ssrc = ssrcIntOf(key);
  const classified = results.classifiedStreams ?? {};
  if (ssrc !== null) {
    if (classified.video != null && String(ssrc) in classified.video) return 'video';
    if (classified.audio != null && String(ssrc) in classified.audio) return 'audio';
  }
  return 'audio';
}

// ==================== 声音问题分类（problem_taxonomy.py） ====================

const SEVERITY_RANK: Record<IssueSeverity, number> = { critical: 0, warning: 1, info: 2 };
const PRIORITY_RANK: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };

export interface TaxonomySpec {
  name: string;
  category: string;
  term: string;
  priority: string;
  feel: string[];
  description: string;
  causes: string[];
  verify: string[];
}

/** 各检测器 issue kind → 问题种类 id（音画质量分析器的 kinds） */
const KIND_TO_PROBLEM: Record<string, string> = {
  rtp_loss: 'loss_artifact',
  howling: 'howling',
  hum: 'buzz',
  clipping: 'clipping',
  clicks: 'transient_noise',
  noise: 'noise_floor',
  low_level: 'low_volume',
  high_level: 'high_volume',
  // 全程未检测到话音（除提示音外基本静音）→ 无声/单通
  no_speech: 'one_way_audio',
  // prompt_tone（回铃音/忙音类提示音）是正常呼叫信号，不进问题分类
  // rtp_order 拆到 clock_anomaly / dup_audio，按 rtp_integrity 字段区分
  // rtp_ok 是正常项，不进分类
};

/** 丢包/断音类的优先级随严重度浮动（清单：严重断续 P1，机器人音/吞字 P2） */
const PRIORITY_BY_SEVERITY: Record<string, Record<string, string>> = {
  loss_artifact: { critical: 'P1', warning: 'P2', info: 'P2' },
  dropouts: { critical: 'P1', warning: 'P2', info: 'P3' },
  latency: { critical: 'P1', warning: 'P2', info: 'P3' },
};

/** 抓包可直接观测/推断的声音问题种类（对照《声音问题种类》清单） */
export const TAXONOMY: Record<string, TaxonomySpec> = {
  one_way_audio: {
    name: '单通 / 无声',
    category: '无声 / 连通',
    term: 'One-way audio / No audio after connect',
    priority: 'P0',
    feel: ['我听不到对方', '对方听不到我', '接通了但没声音'],
    description: '通话已经建立，但某个方向（或两个方向）的声音没有到达。' +
      '抓包里表现为该方向的 RTP 流整段缺失、或流存在但始终无人声。',
    causes: ['媒体没经过 FS 转发（bypass / SDP 改道）', 'NAT / 防火墙拦断 RTP',
      '终端静音、音频焦点或路由错误', '发声端确实没有送出人声'],
    verify: ['看各端上/下行 RTP 是否齐全（本报告"无声诊断"逐腿判定）',
      '对比信令里宣告的媒体地址与实际收发地址', '换终端 / 切外放对比'],
  },
  loss_artifact: {
    name: '丢包失真（电音 / 机关枪 / 吞字）',
    category: '失真 / 断续',
    term: 'Packet loss / PLC artifact',
    priority: 'P2',
    feel: ['电音', '机器人音', '机关枪声', '爆音后静音', '吞字、丢字'],
    description: 'RTP 序号缺口=网络丢了包，播放端只能用 PLC 掩盖或补静音，' +
      '丢得集中就出现电音/机关枪声，丢在字上就是吞字。',
    causes: ['网络拥塞或无线信号弱', '抖动缓冲不足导致的主动丢包', '链路 QoS 未保障'],
    verify: ['抓包看丢包率与突发分布（本报告丢包/时间戳区块）',
      'RTCP RR 的 fraction lost 交叉印证', '换网络环境对比'],
  },
  dropouts: {
    name: '断音 / 内容缺失',
    category: '断续',
    term: 'Dropout / Media gap',
    priority: 'P2',
    feel: ['说话一顿一顿', '突然没声了又恢复', '吞字'],
    description: '发送端媒体时钟出现大段跳变——两包之间少了一段声音。' +
      '对方静音时属于静音抑制的正常省流量；说话时出现则是真缺失。',
    causes: ['发送端采集/编码停顿', '静音抑制误判（把人声当静音）',
      '发送端 CPU 过载'],
    verify: ['对照回放音频听断点位置', '关 VAD/静音抑制对比', '看断点是否落在说话段'],
  },
  clock_anomaly: {
    name: '时钟异常（变调 / 忽快忽慢）',
    category: '协议 / 时钟',
    term: 'Clock drift / Timestamp backward',
    priority: 'P2',
    feel: ['声音变调', '忽快忽慢', '快进感'],
    description: 'RTP 时间戳是发送端给声音盖的媒体时钟标记，正常一路增大；' +
      '倒退说明发送端时钟异常，按序号重排的播放会错位，产生变调与节奏乱。',
    causes: ['发送端时钟/采样率异常', '虚拟机或软终端时钟漂移', '重采样配置错误'],
    verify: ['看时间戳倒退包的捕获时间是否集中（本报告时间戳区块）',
      '换终端或关闭虚拟化音频设备对比'],
  },
  dup_audio: {
    name: '重复音',
    category: '断续',
    term: 'Duplicate / Stuck timestamp',
    priority: 'P2',
    feel: ['同一个字重复两遍', '卡住又继续'],
    description: '序号前进但媒体时间原地踏步——发送端时钟停走或冗余重传，' +
      '同一段声音被播了两遍。',
    causes: ['发送端时钟短暂停走', 'RTP 冗余重传配置', '抓包点重复收录（多抓包合并）'],
    verify: ['对照回放音频确认重复感', '单看某一端抓包排除合并重复'],
  },
  howling: {
    name: '啸叫 / 持续单频音',
    category: '回声 / 设备',
    term: 'Howling / Feedback',
    priority: 'P1',
    feel: ['尖啸声', '刺耳的嘀嘀声', '一直响的单音'],
    description: '频谱上出现"又高又窄又稳定"的谱峰并持续——典型为扬声器' +
      '回授啸叫（外放+麦克风近距离）或单音提示音串入通话。',
    causes: ['免提外放音量过大、麦距太近', 'AEC 失效', '提示音/彩铃串入媒体流'],
    verify: ['戴耳机或切手机听筒对比是否消失', '调低外放音量', '检查终端 AEC 开关'],
  },
  clipping: {
    name: '削波破音',
    category: '失真',
    term: 'Clipping / Overload',
    priority: 'P2',
    feel: ['破音', '炸麦', '沙哑、噼啪'],
    description: '波形顶端被削平（连续大幅值采样一字排开）——发话端增益' +
      '过高把信号削顶，听感沙哑刺耳。',
    causes: ['麦克风增益/发送音量过高', '说话人贴麦太近', 'AGC 上限配置不当'],
    verify: ['调低发送增益后复测', '看本报告削波事件时间与说话段对齐情况'],
  },
  buzz: {
    name: '低频嗡声 / 电流声',
    category: '噪声',
    term: 'Hum / Buzz / Ground loop',
    priority: 'P2',
    feel: ['嗡嗡声', '滋滋电流声', '低频呜呜声'],
    description: '能量集中在低频段（50/100Hz 及其倍频附近）且持续存在——' +
      '典型为电源干扰、接地环路或设备风扇声串入采集。',
    causes: ['电源/接地问题', '音频线与电源线并行', '设备风扇进拾音'],
    verify: ['换电源/换 USB 口对比', '拔掉不必要的外设再看是否消失'],
  },
  transient_noise: {
    name: '瞬态咔哒 / 爆点',
    category: '噪声',
    term: 'Transient noise / Click',
    priority: 'P2',
    feel: ['咔哒声', '噼啪声', '敲击声'],
    description: '孤立的脉冲尖峰（幅度极大、前后邻域都很小）——突发电气' +
      '干扰、设备切换或线路接触的瞬间打火。',
    causes: ['电气干扰', '设备热插拔/切换', '线路接触不良（与"一动就断"相关）'],
    verify: ['对照回放听爆点节奏是否与操作/移动相关', '换线材/换接口对比'],
  },
  noise_floor: {
    name: '底噪偏高',
    category: '噪声',
    term: 'Noise floor',
    priority: 'P3',
    feel: ['沙沙的底噪', '背景一直有声音', '电流麦'],
    description: '静音段（无人说话时）的电平中位数偏高——拾音环境噪声或' +
      '设备自噪声会一直传给对方。',
    causes: ['环境嘈杂', '麦克风增益过高放大自噪声', '降噪（ANS）未开或过弱'],
    verify: ['换安静环境复测', '开关 ANS 对比', '看底噪是持续平稳还是随环境变化'],
  },
  low_volume: {
    name: '音量偏低',
    category: '音量',
    term: 'Low signal level',
    priority: 'P2',
    feel: ['声音小', '发虚', '听不清'],
    description: '话音平均电平低于正常范围——不是杂音，但对方会觉得声音小、' +
      '发虚，常与"听不清"投诉相关。',
    causes: ['麦克风增益/发送音量低', '麦被遮挡或距离远', 'AGC 未生效'],
    verify: ['调高发送增益复测', '录音自测电平', '检查 AGC 配置'],
  },
  high_volume: {
    name: '音量偏高（易破音）',
    category: '音量',
    term: 'High signal level',
    priority: 'P3',
    feel: ['声音太冲', '大点声就炸'],
    description: '话音平均电平接近满幅——再大一点就会削波破音，是削波类' +
      '投诉的前兆。',
    causes: ['发送增益过高', 'AGC 目标电平设置过高'],
    verify: ['调低发送增益', '与削波检测的命中时间互相印证'],
  },
  latency: {
    name: '延迟 / 抖动偏大',
    category: '网络',
    term: 'Latency / Jitter',
    priority: 'P2',
    feel: ['延迟大', '接话慢', '声音时快时慢', '像对讲机'],
    description: '包传输或处理耗时偏大、包到达间隔不稳。延迟大到一定程度' +
      '双方容易抢话，抖动大则播放缓冲压力大、加剧断续。',
    causes: ['网络拥塞/绕路', 'FS 处理或转码开销', '抖动缓冲过大', '蓝牙链路附加延迟'],
    verify: ['看分段延迟链路定位哪一段慢（本报告延迟区块）',
      'RTT/jitter 统计交叉印证', '换有线网络对比'],
  },
  narrowband: {
    name: '窄带编码（发闷 / 水声）',
    category: '设备 / 编解码',
    term: 'Narrowband codec / Possible HFP',
    priority: 'P3',
    feel: ['声音发闷', '像隔了层水', '像老式电话', '蓝牙通话质感'],
    description: '全链路落在 8kHz 窄带编码（如 G.711）：3.4kHz 以上频段' +
      '没有声音，高频细节先天缺失。这不是故障，是编码能力上限；' +
      '若终端走蓝牙，很可能是 HFP/SCO 窄带链路。',
    causes: ['协商只落到 G.711 窄带', '蓝牙 HFP/SCO 链路', 'FS 转码到窄带'],
    verify: ['查 SDP 协商的编码与时钟率（本报告信令区块）',
      '终端切 A2DP / 宽带编码（Opus）对比', '确认 FS 是否参与转码'],
  },
};

/** 抓包层面无法直接确认的听感问题（清单里有、抓包测不到或不可靠） */
export const UNOBSERVABLE: UnobservableItem[] = [
  { name: '风噪', category: '噪声', feel: ['呼呼的风声', '噗噗声'],
    why: '抓包只有编码后的字节流，无法区分"风吹麦克风"与一般环境噪声',
    verify: '户外/遮挡测试，换麦克风位置' },
  { name: '呼吸声 / 喷麦', category: '噪声', feel: ['呼气声很大', '噗——的喷麦声'],
    why: '近讲话学现象，谱形与人声重叠，抓包层无法判别',
    verify: '近讲测试，加防喷罩或开高通滤波（HPF）' },
  { name: '齿音刺耳', category: '噪声', feel: ['咝咝声刺耳'],
    why: '高频增益/EQ 问题，8k 窄带编码下高频已被截掉、抓包看不出来',
    verify: '录齿音对比，调高频 EQ' },
  { name: '忽大忽小（AGC 抽吸）', category: '音量', feel: ['声音一阵大一阵小'],
    why: 'AGC 动态行为需要电平波动统计，当前检测器暂未覆盖（可后续加入）',
    verify: '关 AGC 对比，看是否消失' },
  { name: '一动就断（接触不良）', category: '断续', feel: ['动一下线就没声'],
    why: '表现为整段流消失/长缺口，抓包无法与网络中断区分（FS 转发判定能排除转发侧）',
    verify: '摇动线材/接头测试，换线对比' },
  { name: '听到自己延迟（侧音/回声）', category: '回声', feel: ['听到自己的回声', '自己被延迟播放'],
    why: '需要上/下行音频相关性分析才能确认（可后续版本加入），单看时序不可靠',
    verify: '关侧音/AEC 对比，戴耳机确认是否消失' },
  { name: '双讲压制（半双工）', category: '双讲', feel: ['我一说话对方就断', '同时说话只剩一边'],
    why: 'AEC/降噪的双讲行为在单端抓包里无法与"对方本来就没说话"区分',
    verify: '双讲测试（双方同时说话），关 3A 对比' },
  { name: '特定 App 音频会话异常', category: '平台', feel: ['某个软件里才有问题'],
    why: '音频焦点/路由是终端操作系统行为，抓包不经过终端应用层',
    verify: '换 App 对比，查该 App 的音频权限与 SDK 版本' },
];

/** 抓包里完全无声但"正常"的情况说明，避免把静音抑制误读成问题 */
const NO_PROBLEM_NOTE =
  '以上未命中的听感问题不代表不存在——声学与设备侧现象抓包看不到，见"无法仅凭抓包确认"列表。';

/** 按问题 id 聚合证据；同一问题被多个检测器命中时合并为多条证据。 */
class Collector {
  private readonly found = new Map<string, { evidence: string[]; sources: string[]; severity: IssueSeverity }>();

  constructor(
    private readonly taxonomy: Record<string, TaxonomySpec>,
    private readonly priorityBySeverity: Record<string, Record<string, string>>,
  ) {}

  /** 已命中的问题种类数 */
  get size(): number {
    return this.found.size;
  }

  add(pid: string, evidence: string, severity: IssueSeverity = 'info', source = ''): void {
    let entry = this.found.get(pid);
    if (!entry) {
      entry = { evidence: [], sources: [], severity: 'info' };
      this.found.set(pid, entry);
    }
    if (!entry.evidence.includes(evidence)) entry.evidence.push(evidence);
    if (source && !entry.sources.includes(source)) entry.sources.push(source);
    if (SEVERITY_RANK[severity] < SEVERITY_RANK[entry.severity]) entry.severity = severity;
  }

  /** 按优先级 → 严重度输出问题条目（每种类的固定字段取自分类表）。 */
  output(): ProblemEntry[] {
    const problems: ProblemEntry[] = [];
    for (const [pid, hit] of this.found) {
      const spec = this.taxonomy[pid];
      const severity = hit.severity;
      const priority = this.priorityBySeverity[pid]?.[severity] ?? spec.priority;
      problems.push({
        id: pid,
        name: spec.name,
        category: spec.category,
        term: spec.term,
        priority,
        severity,
        feel: spec.feel,
        description: spec.description,
        evidence: hit.evidence.slice(0, 10),
        sources: hit.sources,
        causes: spec.causes,
        verify: spec.verify,
      });
    }
    problems.sort((a, b) =>
      (PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]) ||
      (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return problems;
  }
}

/** 把分析结果归类到《声音问题种类》清单，输出面向用户的分类报告。 */
export function classifyProblems(results: ReportInput): ProblemClassification {
  const notes: string[] = [];
  let hasAudio = false;
  const col = new Collector(TAXONOMY, PRIORITY_BY_SEVERITY);

  // —— 无声诊断：单通 / 无声（P0） ——
  const audioHealth = results.audioHealth ?? null;
  if (audioHealth?.available) {
    hasAudio = true;
    for (const d of audioHealth.directions ?? []) {
      const v = d.verdict;
      if (v === 'blocked' || v === 'no_source' || v === 'silent_source') {
        col.add('one_way_audio', `${d.label ?? ''}：${d.verdictText ?? ''}`, 'critical', '无声诊断');
      } else if (v === 'silent_path') {
        col.add('one_way_audio', `${d.label ?? ''}：${d.verdictText ?? ''}`, 'warning', '无声诊断');
      }
    }
  } else if (results.audioHealth != null) {
    notes.push('无声诊断不可用（未选中通话或缺对应抓包点），单通/无声只能靠流存在性间接判断');
  }

  // —— FS 媒体转发判定：改道 / 无上行同样是单通形态 ——
  const fsRelay = results.fsRelay ?? {};
  if (fsRelay.available) {
    const v = fsRelay.verdict;
    if (v === 'redirected' || v === 'no_relay') {
      col.add('one_way_audio', `FS 媒体转发：${fsRelay.headline ?? ''}`, 'critical', 'FS 转发判定');
    } else if (v === 'partial_uplink') {
      col.add('one_way_audio', `FS 媒体转发：${fsRelay.headline ?? ''}`, 'warning', 'FS 转发判定');
    }
  }

  // —— 流级丢包（只认音频流；视频流丢包归视频分类器） ——
  for (const [key, data] of Object.entries(results.packetLoss ?? {})) {
    if (streamMediaKind(results, key) === 'video') continue;
    if (data.isClean ?? true) continue;
    hasAudio = true;
    const sev: IssueSeverity = (data.lossRatePct ?? 0) >= 3 ? 'critical' : 'warning';
    col.add('loss_artifact',
      `${data.label ?? ''}: 丢失 ${data.totalLost ?? 0} 包（丢包率 ${f2(data.lossRatePct)}%）`,
      sev, '丢包检测');
  }

  // —— RTCP RR 自报丢包（接收端亲历视角；kind 缺省按音频，旧数据兼容） ——
  for (const [label, entry] of Object.entries(results.rtcp ?? {})) {
    if (entry.kind === 'video') continue;
    const rr = entry.rr;
    if (!rr) continue;
    const lostPct = rr.fractionLostPct ?? 0;
    if (lostPct > 2) {
      hasAudio = true;
      col.add('loss_artifact',
        `${label}: 接收端 RTCP RR 自报丢包 ${lostPct}%（累计 ${rr.cumLost ?? 0} 包）`,
        'warning', 'RTCP');
    }
  }

  // —— 音画质量分析（DSP 检测 + RTP 秩序） ——
  for (const [label, q] of Object.entries(results.audioQuality ?? {})) {
    hasAudio = true;
    const integ = q.rtpIntegrity ?? {};
    if (integ.tsBackward) {
      col.add('clock_anomaly',
        `${label}: RTP 时间戳倒退 ${integ.tsBackward} 处——发送端时钟异常，播放重排会变调、忽快忽慢`,
        'critical', '音画质量');
    }
    if (integ.tsDuplicate) {
      col.add('dup_audio',
        `${label}: RTP 时间戳重复 ${integ.tsDuplicate} 处——同一段声音会被播两遍`,
        'warning', '音画质量');
    }
    for (const issue of q.issues ?? []) {
      const pid = KIND_TO_PROBLEM[issue.kind ?? ''];
      if (pid) col.add(pid, `${label}: ${issue.message ?? ''}`, asSeverity(issue.severity, 'info'), '音画质量');
    }
    if (q.decodable) {
      const codec = q.codec ?? '';
      if (codec.includes('PCMU') || codec.includes('PCMA') || codec.includes('G.711')) {
        col.add('narrowband',
          `${label}: 编码为 ${codec}（8kHz 窄带），3.4kHz 以上频段没有声音——听感发闷属编码特性，` +
          '若走蓝牙则很可能是HFP/SCO 链路',
          'info', '编码检查');
      }
    }
  }

  // —— 时间戳连续性（发送端媒体时钟行为；frame 模式是视频流，跳过） ——
  for (const [label, data] of Object.entries(results.tsContinuity ?? {})) {
    if (data.mode === 'frame') continue;
    const gap = data.totalMediaGapMs ?? 0;
    if (data.jumpCount) {
      hasAudio = true;
      const sev: IssueSeverity = gap >= 300 ? 'critical' : gap >= 50 ? 'warning' : 'info';
      col.add('dropouts',
        `${label}: 声音内容断开 ${data.jumpCount} 处，累计缺少约 ${gapHuman(gap)}的声音` +
        (gap >= 50 ? '（含静音抑制的正常缺口，断点落在说话段才是问题）' : '（量很小，基本无感）'),
        sev, '时间戳连续性');
    }
    if (data.backwardCount) {
      hasAudio = true;
      col.add('clock_anomaly',
        `${label}: 声音时间往回走 ${data.backwardCount} 处（发送端时钟异常）`,
        'critical', '时间戳连续性');
    }
    if (data.duplicateCount) {
      hasAudio = true;
      col.add('dup_audio',
        `${label}: 同一时刻声音重复 ${data.duplicateCount} 处`,
        'warning', '时间戳连续性');
    }
  }

  // —— 延迟 / 抖动 ——
  const fsDelay = results.fsDelay ?? {};
  if ((fsDelay.count ?? 0) > 0) {
    if ((fsDelay.mean ?? 0) >= 50) {
      col.add('latency',
        `FS 内部处理延迟均值 ${f1(fsDelay.mean)}ms（P95 ${f1(fsDelay.p95)}ms），明显偏高`,
        'critical', '延迟分析');
    } else if ((fsDelay.mean ?? 0) >= 20) {
      col.add('latency',
        `FS 内部处理延迟均值 ${f1(fsDelay.mean)}ms，偏高`,
        'warning', '延迟分析');
    }
  }
  for (const [label, data] of Object.entries(results.jitter ?? {})) {
    if (streamMediaKind(results, label) === 'video') continue;
    if ((data.std ?? 0) > 10) {
      hasAudio = true;
      col.add('latency',
        `${label}: 包间隔抖动偏大（标准差 ${f1(data.std)}ms）——播放缓冲压力大，会加剧断续`,
        'warning', '抖动分析');
    }
  }
  const delayChains = results.delayChains ?? {};
  if (delayChains.available) {
    for (const d of delayChains.directions ?? []) {
      if (d.verdict === 'high') {
        col.add('latency', `延迟链路·${d.label ?? ''}: ${d.verdictText ?? ''}`, 'warning', '延迟链路');
      }
    }
    for (const r of delayChains.roundtrip ?? []) {
      if (r.status === 'high') {
        col.add('latency',
          `延迟链路·${r.pair ?? ''}: 往返 ${r.ms ?? 0}ms，链路整体偏慢`,
          'warning', '延迟链路');
      }
    }
  }

  // —— 适用范围与说明 ——
  if (results.mediaType === 'video') {
    notes.push('本次仅分析了视频流，声音问题分类不适用');
  }
  if (results.checks && results.checks.quality === false) {
    notes.push('未勾选音画质量分析，啸叫/削波/底噪等杂音类问题本次未检测');
  }
  if (!hasAudio && col.size === 0) {
    notes.push('分析结果中没有音频流的检测数据，无法做声音问题分类');
  }

  const problems = col.output();
  // summary 只统计真正的问题（warning/critical）；info 级条目（如窄带编码
  // 特性说明）是解释性信息，不参与"发现问题"的计数，避免正常 G.711 通话
  // 被总结成"检出问题"
  const real = problems.filter((p) => p.severity !== 'info');
  let summary: string;
  if (real.length > 0) {
    const worst = real[0];
    summary = `检出 ${real.length} 类声音问题，最需要先处理的是 ${worst.priority}·${worst.name}（${worst.category}）`;
  } else if (problems.length > 0) {
    summary = '抓包层面未发现可归类的声音问题（下方 info 级条目为编码特性说明，不是故障）';
  } else {
    summary = hasAudio
      ? '抓包层面未发现可归类的声音问题'
      : '没有音频流检测数据，声音问题分类不可用';
  }

  return {
    available: hasAudio || problems.length > 0,
    problems,
    unobservable: UNOBSERVABLE,
    summary,
    notes: notes.concat(problems.length > 0 ? [NO_PROBLEM_NOTE] : []),
  };
}

// ==================== 视频问题分类（video_problem_taxonomy.py） ====================

/** 丢包/关键帧类优先级随严重度浮动（清单：弱网花屏 P1 起评，卡顿类 P2） */
const VIDEO_PRIORITY_BY_SEVERITY: Record<string, Record<string, string>> = {
  no_video: { critical: 'P0', warning: 'P1' },
  video_loss: { critical: 'P1', warning: 'P2' },
  keyframe_issue: { critical: 'P0', warning: 'P1', info: 'P2' },
  video_clock_anomaly: { critical: 'P1', warning: 'P2' },
  video_latency: { critical: 'P1', warning: 'P2', info: 'P3' },
  low_fps: { warning: 'P2', info: 'P3' },
};

/** 抓包可直接观测/推断的视频问题种类（对照《视频问题》清单） */
export const VIDEO_TAXONOMY: Record<string, TaxonomySpec> = {
  no_video: {
    name: '无画面 / 黑屏 / 单通视频',
    category: '无画面 / 连通',
    term: 'No video / Black screen / One-way video',
    priority: 'P0',
    feel: ['完全没画面、黑屏', '有声音没画面', '我看不到对方',
      '对方看不到我', '双方都没画面'],
    description: '音频在走但视频流缺失或断了单边——抓包里表现为该端' +
      '没有视频 RTP 上行、FS 从未下发视频，或媒体根本没经' +
      '过 FS 转发。',
    causes: ['媒体没经过 FS 转发（bypass / SDP 改道）',
      'NAT / 防火墙拦断视频 RTP（视频端口与音频分开）',
      '发送端没产出视频（摄像头/采集侧，见下方"无法仅凭抓包确认"）',
      'SDP 视频协商失败（sendonly/inactive/端口 0）'],
    verify: ['看各端上/下行视频 RTP 是否齐全（本报告 FS 转发判定）',
      '对比信令里视频 m 行的协商方向与端口',
      '两端看本地预览：预览正常而对端无画面 → 传输/转发侧'],
  },
  corrupt_video: {
    name: '花屏 / 马赛克 / 绿屏',
    category: '花屏 / 解码',
    term: 'Corrupted video / Macroblocking / Decoder artifact',
    priority: 'P1',
    feel: ['花屏', '马赛克', '绿屏', '画面烂掉'],
    description: '帧数据因丢包/分片不完整而破损，解码层必然出错——' +
      '受损画面会持续到下一个关键帧（IDR）刷新。',
    causes: ['丢包导致参考帧丢失、FU-A 分片缺包',
      '解码器异常（硬解兼容性，见"无法仅凭抓包确认"）',
      '发送端时钟异常导致帧序错位'],
    verify: ['看破损帧数与 ffmpeg 解码校验（本报告音画质量区块）',
      '丢包处与花屏时间对齐即可定位网络侧',
      '解码校验通过而仍花屏 → 查终端硬解/渲染'],
  },
  video_loss: {
    name: '弱网花屏 / 丢包',
    category: '网络 / 传输',
    term: 'Packet loss / Corruption',
    priority: 'P2',
    feel: ['弱网就花', '卡的时候花一下', '花屏过几秒自己好'],
    description: '视频对丢包远比音频敏感：一帧内丢包整帧报废，参考链' +
      '断掉后花屏持续到关键帧；接收端 NACK 重传与 RTCP RR ' +
      '自报丢包都是网络侧的亲历佐证。',
    causes: ['带宽不足或无线信号弱', '抖动缓冲不足导致的主动丢包',
      '链路 QoS 未保障（视频与其他流量抢带宽）'],
    verify: ['看丢包率与花屏影响时长（本报告丢包/音画质量区块）',
      'RTCP RR / NACK 交叉印证接收端实际收到什么',
      '换网络环境对比；确认码率自适应是否生效'],
  },
  keyframe_issue: {
    name: '关键帧问题（出画面慢 / 花屏不恢复）',
    category: '解码 / 传输',
    term: 'PLI/FIR storm / Slow first frame / No IDR',
    priority: 'P1',
    feel: ['半天才出画面', '花屏很久才恢复', '一卡就卡好几个关键帧间隔'],
    description: '关键帧（IDR）是花屏后唯一的自愈手段：全程无 IDR 时' +
      '丢一次包就花到挂断，IDR 间隔越长恢复越慢；接收端频繁' +
      '发 PLI/FIR 说明解码层反复在等参考帧。',
    causes: ['终端关键帧间隔（GOP）配置过大', '丢包/解码失败触发 PLI/FIR',
      '上行带宽不足，关键帧发不出去（大帧被拆丢）'],
    verify: ['看 IDR 数量与最长间隔（本报告音画质量区块）',
      'RTCP PLI/FIR 次数（本报告 RTCP 区块）',
      '建议终端把关键帧间隔控制在 2~4 秒'],
  },
  video_clock_anomaly: {
    name: '发送端时钟异常（冻结 / 花屏风险）',
    category: '卡顿 / 流畅',
    term: 'Timestamp backward',
    priority: 'P1',
    feel: ['画面突然停住', '卡一下又跳一块', '冻结'],
    description: 'RTP 时间戳是发送端给视频帧盖的媒体时钟标记，按序号' +
      '排列应单调递增；倒退说明发送端时钟异常，按序号重组' +
      '的帧序与真实播放序错位。',
    causes: ['发送端时钟/采集驱动异常', '虚拟机或软终端时钟漂移',
      '抓包点重复收录（多抓包合并）'],
    verify: ['看时间戳倒退位置（本报告时间戳/音画质量区块）',
      '换终端或关闭虚拟化设备对比'],
  },
  video_latency: {
    name: '延迟 / 卡顿',
    category: '卡顿 / 流畅',
    term: 'Latency / Jitter / Stuttering',
    priority: 'P2',
    feel: ['延迟大', '卡顿、断断续续', '画面跟不上人动'],
    description: '包传输或处理耗时偏大、到达间隔不稳。视频缓冲压力' +
      '大于音频，抖动大时表现为画面一顿一顿。',
    causes: ['网络拥塞/绕路', 'FS 处理或转码开销', '编码端 CPU 不足（见"无法仅凭抓包确认"）'],
    verify: ['看分段延迟链路定位哪一段慢（本报告延迟区块）',
      'RTT/jitter 统计交叉印证', '换有线网络对比'],
  },
  low_fps: {
    name: '帧率偏低',
    category: '清晰度 / 画质',
    term: 'Low FPS',
    priority: 'P2',
    feel: ['画面不流畅', '一顿一顿', '拖影'],
    description: '按 RTP 时间戳估算的实际帧率明显低于视频通话常态' +
      '（15fps 以下）——弱光降帧、编码端过载或带宽自适应' +
      '降级都会表现为帧率掉下来。',
    causes: ['弱光下曝光时间变长，采集自动降帧', '编码端 CPU 过载',
      '带宽自适应压低帧率', '变帧率编码（屏幕共享等）本身不均匀'],
    verify: ['看估算帧率（本报告时间戳区块，按 90kHz 时钟换算）',
      '改善光照后对比', '看终端采集/编码 FPS 统计'],
  },
};

/** 抓包层面无法直接确认的观感问题（清单里有、抓包测不到），只给人工验证方法 */
export const VIDEO_UNOBSERVABLE: UnobservableItem[] = [
  { name: '摄像头打不开 / 被占用 / 权限拒绝', category: '摄像头 / 采集',
    feel: ['摄像头打不开', '本地预览就全黑', '提示无权限'],
    why: '采集发生在终端本地，抓包只见"有没有视频 RTP"，分不清"没采集"还是"采集了没发"',
    verify: '看本地预览是否正常；系统相机能否打开；检查系统设置里的摄像头权限；关掉占用摄像头的其他应用' },
  { name: '前后摄切换失败', category: '摄像头 / 采集',
    feel: ['一切换前/后摄就黑屏或卡死'],
    why: '设备枚举与采集 Surface 重建是终端行为，媒体流上无痕迹',
    verify: '换设备对比复现；看切换瞬间终端日志' },
  { name: '模糊 / 分辨率低 / 磨皮发虚', category: '清晰度 / 画质',
    feel: ['模糊看不清', '分辨率低', '磨皮过度发虚'],
    why: '模糊是主观观感；分辨率/码率在码流元数据里，当前抓包分析未解析（后续可从 SPS 提取）',
    verify: '关美颜/滤镜对比；查终端分辨率与码率统计；确认对焦（AF）是否正常' },
  { name: '偏色 / 过暗 / 过曝 / 闪烁', category: '颜色 / 曝光',
    feel: ['脸色发绿/发紫', '逆光黑脸', '灯光下画面闪'],
    why: '色彩与曝光是像素级现象，RTP 抓包不逐像素可见（需解码出帧做图像分析，当前未做）',
    verify: '换光源/开抗闪烁（防工频干扰）对比；调曝光补偿/WDR；换设备对比' },
  { name: '旋转 / 镜像 / 拉伸 / 黑边', category: '方向 / 比例',
    feel: ['画面转了90度', '人是镜像的', '画面被压扁/有黑边'],
    why: '旋转由采集 metadata、镜像与拉伸由渲染端决定，编码数据本身不携带这些效果',
    verify: '换设备/换播放端对比；锁定屏幕方向重进；查渲染端宽高比与 letterbox 设置' },
  { name: '音画不同步', category: '音画同步',
    feel: ['口型对不上', '画面比声音慢/快'],
    why: '需要用 RTCP SR 的 NTP↔RTP 映射把音频与视频两路时钟对齐，中间抓包点时钟又与发送端不同步，offset 算不准',
    verify: '看终端 SDK 的 A/V offset 统计；换网络/设备对比；确认两端时钟源' },
  { name: '屏幕共享黑屏 / 看不到鼠标', category: '屏幕共享',
    feel: ['一共享就黑屏', '共享里没有鼠标'],
    why: 'DRM 保护、窗口/屏幕采集与光标捕获都是终端采集设置，抓包只见结果',
    verify: '换共享对象（窗口/标签页）对比；关硬件加速；确认采集权限与光标捕获开关' },
  { name: '越用越卡 / 发热掉帧 / 省电模式', category: '性能 / 设备',
    feel: ['越用越卡', '机身发烫后掉帧', '开省电就卡'],
    why: '温控降频是终端系统行为，媒体流上只见"帧变少了"，分不清弱网还是降频',
    verify: '关省电模式、散热后复测；看终端 CPU/GPU 频率与温度' },
  { name: '特定机型异常', category: '性能 / 设备',
    feel: ['只有某款设备有问题'],
    why: '硬编硬解兼容性要看终端解码器日志，码流层面大多正常',
    verify: '换机型复测；关硬件编解码对比' },
  { name: '美颜 / 虚拟背景 / 滤镜类前处理异常', category: '前处理 / 算法',
    feel: ['虚拟背景边缘闪烁', '背景虚化穿帮', '滤镜偏色'],
    why: '前处理发生在编码之前，抓包拿到的是处理后的码流，无法还原算法行为',
    verify: '逐项关闭美颜/虚拟背景/滤镜/降噪/防抖对比' },
];

const VIDEO_NO_PROBLEM_NOTE =
  '以上未命中的观感问题不代表不存在——采集、渲染、算法侧现象抓包看不到，见"无法仅凭抓包确认"列表。';

// PLI/FIR 请求关键帧次数达到该值才报（偶发一两次属解码器正常初始化）
const PLI_STORM_MIN = 3;
// 视频丢包率 ≥1% 即按"花到关键帧"评估（视频对丢包远比音频敏感）
const VIDEO_LOSS_CRITICAL_PCT = 1.0;

/** 把分析结果归类到《视频问题种类》清单，输出面向用户的分类报告。 */
export function classifyVideoProblems(results: ReportInput): ProblemClassification {
  const notes: string[] = [];
  const videoBuckets = results.classifiedStreams?.video ?? {};
  const hasVideo = Object.keys(videoBuckets).length > 0 || Object.keys(results.videoQuality ?? {}).length > 0;
  const col = new Collector(VIDEO_TAXONOMY, VIDEO_PRIORITY_BY_SEVERITY);

  // —— FS 媒体转发判定：改道 / 无上行时视频同样断流（P0 形态） ——
  const fsRelay = results.fsRelay ?? {};
  const relayDevices = fsRelay.devices ?? [];
  const relayVerdict = fsRelay.verdict;
  if (fsRelay.available) {
    if (relayVerdict === 'redirected' || relayVerdict === 'no_relay') {
      col.add('no_video', `FS 媒体转发：${fsRelay.headline ?? ''}`, 'critical', 'FS 转发判定');
    } else if (relayVerdict === 'partial_uplink') {
      col.add('no_video', `FS 媒体转发：${fsRelay.headline ?? ''}`, 'warning', 'FS 转发判定');
    }

    // 单通视频：一端视频上行正常、FS 却从未向另一端下发视频。
    // 改道（bypass）后 FS 侧本来就看不到端到端媒体，不下此结论；
    // 通话里没有任何视频上行则多半是纯音频通话，也不下。
    if (relayVerdict !== 'redirected' && relayDevices.length > 0) {
      for (const upDev of relayDevices) {
        if (upDev.uplink.video.pkts <= 0) continue;
        for (const downDev of relayDevices) {
          if (downDev.ip === upDev.ip) continue;
          if (downDev.downlink.video.pkts <= 0 && downDev.uplink.audio.pkts > 0) {
            col.add(
              'no_video',
              `${upDev.label} 上行了视频（${upDev.uplink.video.pkts} 包），但 FS ` +
              `从未向 ${downDev.label} 下发过视频——${downDev.label} 侧看不到` +
              `${upDev.label} 的画面（单通视频）`,
              'critical', 'FS 转发判定');
          }
        }
      }
    }
  }

  // —— 音画质量分析（花屏 / 解码 / 时钟） ——
  // broken_nal/decode_errors → 花屏；video_loss/no_idr/idr_gap → 各归其类；
  // rtp_order 不经 kind 映射（与音频分类器同构，直接读 rtp_integrity）
  const VQ_KIND_MAP: Record<string, string> = {
    broken_nal: 'corrupt_video',
    decode_errors: 'corrupt_video',
    video_loss: 'video_loss',
    no_idr: 'keyframe_issue',
    idr_gap: 'keyframe_issue',
  };
  for (const [label, q] of Object.entries(results.videoQuality ?? {})) {
    const integ = q.rtpIntegrity ?? {};
    if (integ.tsBackward) {
      col.add('video_clock_anomaly',
        `${label}: RTP 时间戳倒退 ${integ.tsBackward} 处——发送端时钟异常，帧序重排会错位，花屏/冻结风险高`,
        'critical', '音画质量');
    }
    for (const issue of q.issues ?? []) {
      const pid = VQ_KIND_MAP[issue.kind ?? ''];
      if (pid) col.add(pid, `${label}: ${issue.message ?? ''}`, asSeverity(issue.severity, 'info'), '音画质量');
    }
  }

  // —— 流级丢包（只认视频流；视频质量分析已覆盖的流不重复报） ——
  const vqLabels = new Set(Object.keys(results.videoQuality ?? {}));
  for (const [key, data] of Object.entries(results.packetLoss ?? {})) {
    if (streamMediaKind(results, key) !== 'video') continue;
    if ((data.isClean ?? true) || (data.label != null && vqLabels.has(data.label))) continue;
    const sev: IssueSeverity =
      (data.lossRatePct ?? 0) >= VIDEO_LOSS_CRITICAL_PCT ? 'critical' : 'warning';
    col.add('video_loss',
      `${data.label ?? ''}: 丢失 ${data.totalLost ?? 0} 包（丢包率 ${f2(data.lossRatePct)}%）——丢包处画面会` +
      '花屏直到下一个关键帧刷新',
      sev, '丢包检测');
  }

  // —— RTCP：接收端自报丢包 / NACK 重传 / PLI-FIR 关键帧请求 ——
  for (const [label, entry] of Object.entries(results.rtcp ?? {})) {
    if (entry.kind !== 'video') continue;
    const rr = entry.rr;
    if (rr && (rr.fractionLostPct ?? 0) > 0.5) {
      col.add('video_loss',
        `${label}: 接收端 RTCP RR 自报丢包 ${rr.fractionLostPct}%（累计 ${rr.cumLost ?? 0} 包）`,
        'warning', 'RTCP');
    }
    const fb = entry.fb ?? {};
    const nack = fb.nack;
    if (nack && nack.requested) {
      col.add('video_loss',
        `${label}: 接收端 NACK 指名重传 ${nack.requested} 个包（${nack.packets ?? 0} 次）——接收端确实在丢包并补救`,
        'warning', 'RTCP');
    }
    const pli = fb.pli;
    const fir = fb.fir;
    const reqCnt = (pli?.count ?? 0) + (fir?.count ?? 0);
    if (reqCnt >= PLI_STORM_MIN) {
      col.add('keyframe_issue',
        `${label}: 接收端请求关键帧 ${reqCnt} 次（PLI ${pli?.count ?? 0} / FIR ${fir?.count ?? 0}）` +
        '——解码层反复在等参考帧，对应画面在花屏或停住',
        'warning', 'RTCP');
    }
  }

  // —— 时间戳连续性（只看 frame 模式 = 视频流）+ 帧率估算 ——
  for (const [label, data] of Object.entries(results.tsContinuity ?? {})) {
    if (data.mode !== 'frame') continue;
    if (data.backwardCount) {
      col.add('video_clock_anomaly',
        `${label}: 视频时间戳往回走 ${data.backwardCount} 处（发送端时钟异常）`,
        'critical', '时间戳连续性');
    }
    const rate = data.clockRate;
    const medianDelta = data.medianTsDelta ?? 0;
    if (rate && medianDelta > 0 && (data.packetCount ?? 0) >= 100) {
      const fps = rate / medianDelta;
      if (fps < 10) {
        col.add('low_fps',
          `${label}: 估算帧率仅 ${fps.toFixed(1)} fps（按 RTP 时间戳估算；变帧率编码如屏幕共享会天然偏低，仅供参考）`,
          'warning', '时间戳连续性');
      } else if (fps < 15) {
        col.add('low_fps',
          `${label}: 估算帧率约 ${fps.toFixed(1)} fps，偏低（变帧率编码下仅供参考）`,
          'info', '时间戳连续性');
      }
    }
  }

  // —— 延迟 / 抖动（只认视频流） ——
  const fsDelay = results.fsDelay ?? {};
  if ((fsDelay.count ?? 0) > 0) {
    if ((fsDelay.mean ?? 0) >= 50) {
      col.add('video_latency',
        `FS 内部处理延迟均值 ${f1(fsDelay.mean)}ms（P95 ${f1(fsDelay.p95)}ms），视频画面同样被拖慢`,
        'critical', '延迟分析');
    } else if ((fsDelay.mean ?? 0) >= 20) {
      col.add('video_latency',
        `FS 内部处理延迟均值 ${f1(fsDelay.mean)}ms，偏高`,
        'warning', '延迟分析');
    }
  }
  for (const [label, data] of Object.entries(results.jitter ?? {})) {
    if (streamMediaKind(results, label) !== 'video') continue;
    if ((data.std ?? 0) > 10) {
      col.add('video_latency',
        `${label}: 包间隔抖动偏大（标准差 ${f1(data.std)}ms）——解码缓冲压力大，表现为画面一顿一顿`,
        'warning', '抖动分析');
    }
  }

  // —— 适用范围与说明 ——
  if (Object.keys(videoBuckets).length === 0 && Object.keys(results.videoQuality ?? {}).length === 0) {
    notes.push('抓包里没有视频流的检测数据：若该通话本应有视频（用户报"没画面"），先查 SDP 视频协商、' +
      '摄像头权限与占用——属于终端/协商侧，抓包层面只能确认"没有视频 RTP"');
  }
  if (results.mediaType === 'audio') {
    notes.push('本次仅分析了音频流，视频问题分类不适用');
  }
  if (results.checks && results.checks.quality === false) {
    notes.push('未勾选音画质量分析，花屏/解码类细项本次未检测（仅覆盖丢包、时间戳、转发路径等流级证据）');
  }

  const problems = col.output();
  const real = problems.filter((p) => p.severity !== 'info');
  let summary: string;
  if (real.length > 0) {
    const worst = real[0];
    summary = `检出 ${real.length} 类视频问题，最需要先处理的是 ${worst.priority}·${worst.name}（${worst.category}）`;
  } else if (problems.length > 0) {
    summary = '抓包层面未发现可归类的视频问题（下方 info 级条目为说明性信息，不是故障）';
  } else {
    summary = hasVideo
      ? '抓包层面未发现可归类的视频问题'
      : '没有视频流检测数据，视频问题分类不可用';
  }

  return {
    available: hasVideo || problems.length > 0,
    problems,
    unobservable: VIDEO_UNOBSERVABLE,
    summary,
    notes: notes.concat(problems.length > 0 ? [VIDEO_NO_PROBLEM_NOTE] : []),
  };
}

// ==================== 报告主体（reporter.py） ====================

/** 构建网络拓扑摘要。 */
function buildTopology(results: ReportInput): ReportTopology {
  const topology: ReportTopology = { endpoints: [], server: null, connections: [] };
  for (const [role, info] of Object.entries(results.ipsInfo ?? {})) {
    for (const ip of info.ips ?? []) {
      if (ip !== '0.0.0.0' && ip !== '255.255.255.255' && !ip.startsWith('224.')) {
        topology.endpoints.push({ role, ip, streamCount: info.streamCount ?? 0 });
      }
    }
  }
  const serverIp = results.detectedServerIp;
  if (serverIp) topology.server = serverIp;
  return topology;
}

/** SSRC 键 → '0x%08x' 展示串 */
function ssrcHex(key: string): string {
  const n = Number(key);
  return Number.isInteger(n) && n >= 0 ? `0x${n.toString(16).padStart(8, '0')}` : key;
}

/** 构建流摘要。 */
function buildStreamSummary(results: ReportInput): ReportStreamSummary {
  const classified = results.classifiedStreams ?? {};
  const summary: ReportStreamSummary = {
    totalAudio: Object.keys(classified.audio ?? {}).length,
    totalVideo: Object.keys(classified.video ?? {}).length,
    totalUnknown: Object.keys(classified.unknown ?? {}).length,
    audioStreams: [],
    videoStreams: [],
  };
  for (const [ssrc, info] of Object.entries(classified.audio ?? {})) {
    summary.audioStreams.push({
      ssrc: ssrcHex(ssrc),
      pt: info.pt ?? [],
      packetCount: info.count ?? 0,
      ips: info.ips ?? [],
    });
  }
  for (const [ssrc, info] of Object.entries(classified.video ?? {})) {
    summary.videoStreams.push({
      ssrc: ssrcHex(ssrc),
      pt: info.pt ?? [],
      packetCount: info.count ?? 0,
      ips: info.ips ?? [],
    });
  }
  return summary;
}

/** 构建延迟摘要。 */
function buildDelaySummary(results: ReportInput): ReportDelaySummary {
  const fsDelay = results.fsDelay ?? {};
  return {
    fsInternal: {
      mean: fsDelay.mean ?? 0,
      p50: fsDelay.p50 ?? 0,
      p95: fsDelay.p95 ?? 0,
      p99: fsDelay.p99 ?? 0,
      max: fsDelay.max ?? 0,
      std: fsDelay.std ?? 0,
      count: fsDelay.count ?? 0,
      outliers50ms: outliers50(fsDelay),
      outliers100ms: outliers100(fsDelay),
      available: (fsDelay.count ?? 0) > 0,
    },
    crossCapture: (results.crossDelays ?? []).map((cd) => ({
      label: cd.label ?? '',
      mean: cd.mean ?? 0,
      p95: cd.p95 ?? 0,
      clockOffsetMs: cd.clockOffsetMs ?? 0,
    })),
    endToEnd: results.endToEnd ?? null,
  };
}

/** 构建抖动摘要。 */
function buildJitterSummary(results: ReportInput): Record<string, ReportJitterEntry> {
  const summary: Record<string, ReportJitterEntry> = {};
  for (const [label, data] of Object.entries(results.jitter ?? {})) {
    summary[label] = {
      mean: data.mean ?? 0,
      median: data.median ?? 0,
      std: data.std ?? 0,
      p95: data.p95 ?? 0,
      abnormalCount: data.abnormalCount ?? 0,
      expectedInterval: data.expectedInterval ?? 0,
    };
  }
  return summary;
}

/** 构建丢包摘要。 */
function buildLossSummary(results: ReportInput): Record<string, ReportLossEntry> {
  const summary: Record<string, ReportLossEntry> = {};
  for (const [ssrc, data] of Object.entries(results.packetLoss ?? {})) {
    summary[ssrc] = {
      label: data.label ?? '',
      totalPackets: data.totalPackets ?? 0,
      totalLost: data.totalLost ?? 0,
      lossRatePct: data.lossRatePct ?? 0,
      reorderCount: data.reorderCount ?? 0,
      isClean: data.isClean ?? true,
    };
  }
  return summary;
}

/** 构建时间戳连续性摘要。 */
function buildTsSummary(results: ReportInput): ReportTsContinuity {
  const streams: Record<string, ReportTsStream> = {};
  for (const [label, data] of Object.entries(results.tsContinuity ?? {})) {
    streams[label] = {
      isContinuous: data.isContinuous ?? true,
      packetCount: data.packetCount ?? 0,
      pt: data.pt ?? null,
      clockRate: data.clockRate ?? null,
      mode: data.mode ?? null,
      packetDurationMs: data.packetDurationMs ?? null,
      eventCount: data.eventCount ?? 0,
      jumpCount: data.jumpCount ?? 0,
      backwardCount: data.backwardCount ?? 0,
      reorderCount: data.reorderCount ?? 0,
      duplicateCount: data.duplicateCount ?? 0,
      wrapCount: data.wrapCount ?? 0,
      totalMediaGapMs: data.totalMediaGapMs ?? 0,
      // 事件明细带可读时间与前后包信息（最多 20 条，完整计数见上面各字段）
      events: (data.events ?? []).slice(0, 20).map((ev) => ({
        timeStr: fmtTimeOfDay(ev.time),
        kind: ev.kind,
        seq: ev.seq,
        ts: ev.ts ?? null,
        prevSeq: ev.prevSeq ?? null,
        prevTs: ev.prevTs ?? null,
        tsDelta: ev.tsDelta,
        mediaGapMs: ev.mediaGapMs ?? null,
        arrivalGapMs: ev.arrivalGapMs ?? null,
      })),
    };
  }
  return { streams };
}

/** 构建时钟偏移摘要。 */
function buildClockSummary(results: ReportInput): ReportClockOffset {
  const clockInfo = results.clockInfo ?? {};
  return {
    offsets: clockInfo.offsets ?? {},
    maxOffsetMs: clockInfo.maxOffset ?? 0,
    warning: clockInfo.warning ?? null,
  };
}

/** 生成时间戳异常的直白解释（分现象说明 + 影响评估）。 */
function tsExplain(data: TsContinuityStatInput, gapMs: number): string {
  const lines = [
    '发送端给每一包声音都盖了一个"时间戳"，标记这段声音在整通电话里的位置，' +
    '正常情况下它随包一路增大。异常就是它的位置对不上：',
  ];
  if (data.jumpCount) {
    lines.push('・声音内容突然断开：相邻两包之间少了一段声音。如果对方正处于静音（没说话），' +
      '这是"静音抑制"的正常省流量做法；如果发生在有人说话时，说明发送端丢了一段声音。');
  }
  if (data.backwardCount) {
    lines.push('・声音时间往回走：包到达的先后顺序没乱，但时间戳却倒退——' +
      '通常是发送端（终端或服务器）时钟异常，可能表现为卡顿、杂音。');
  }
  if (data.reorderCount) {
    lines.push('・数据包晚到/乱序：网络把包的先后顺序打乱了，播放端一般能自动恢复，通常无需处理。');
  }
  if (data.duplicateCount) {
    lines.push('・同一时刻声音重复：同一段声音被发了两遍（或发送端时钟停了一下），' +
      '可能是发送端故障或冗余重传。');
  }
  if (gapMs >= 1) {
    lines.push(`影响评估：整通电话累计缺少约 ${gapHuman(gapMs)}的声音内容。`);
  } else {
    lines.push('影响评估：声音内容本身没有缺失。');
  }
  return lines.join('\n');
}

/** 生成结论（所有面向用户的文案使用中文）。 */
function buildConclusion(results: ReportInput): ReportConclusion {
  const fsDelay = results.fsDelay ?? {};
  const jitter = results.jitter ?? {};
  const packetLoss = results.packetLoss ?? {};

  const issues: ReportIssue[] = [];
  const okItems: string[] = [];

  // 抓包完整性说明（截短/文件尾损坏）：数据不完整不影响继续分析，但
  // 所有统计与媒体重建都要带着"可能有缺漏"的前提来读，放在问题列表最前
  const dataNotes: ReportIssue[] = [];
  for (const [role, info] of Object.entries(results.captureIntegrity ?? {})) {
    if (info.status !== 'warn') continue;
    const fname = results.captureRoles?.[role] ?? role;
    for (const note of info.notes ?? []) {
      dataNotes.push({
        severity: 'warning',
        message: `抓包可能不完整（${fname}）：${note}。分析已按现有数据继续，相关统计与媒体重建可能受影响。`,
      });
    }
  }

  // FS 内部延迟评估
  if ((fsDelay.count ?? 0) > 0) {
    if ((fsDelay.mean ?? 0) < 20 && (fsDelay.p95 ?? 0) < 50) {
      okItems.push('FS 内部处理延迟健康（均值 < 20ms）');
    } else if ((fsDelay.mean ?? 0) < 50) {
      issues.push({
        severity: 'warning',
        message: `FS 处理延迟偏高（均值 ${f1(fsDelay.mean)}ms）`,
      });
    } else {
      issues.push({
        severity: 'critical',
        message: `FS 处理延迟过高（均值 ${f1(fsDelay.mean)}ms）`,
      });
    }

    if ((fsDelay.outliers50Ms ?? fsDelay.outliers50ms ?? 0) > 0) {
      issues.push({
        severity: 'warning',
        message: `检测到 ${outliers50(fsDelay)} 次 > 50ms 的延迟尖峰`,
      });
    }
  } else {
    issues.push({
      severity: 'info',
      message: '未捕获 FS 抓包——无法测量 FS 内部处理延迟',
    });
  }

  // 抖动评估
  for (const [label, data] of Object.entries(jitter)) {
    if ((data.std ?? 0) > 10) {
      issues.push({
        severity: 'warning',
        message: `${label}: 抖动偏大（标准差 ${f1(data.std)}ms）`,
      });
    } else if ((data.abnormalCount ?? 0) > 0) {
      issues.push({
        severity: 'info',
        message: `${label}: 检测到 ${data.abnormalCount} 处异常包间隔`,
      });
    } else {
      okItems.push(`${label}: 间隔稳定（标准差 ${f1(data.std)}ms）`);
    }
  }

  // 丢包评估
  if (Object.keys(packetLoss).length > 0) {
    const allClean = Object.values(packetLoss).every((d) => d.isClean ?? true);
    if (allClean) {
      okItems.push('所有流均未检测到丢包');
    } else {
      for (const [, data] of Object.entries(packetLoss)) {
        if (!(data.isClean ?? true)) {
          issues.push({
            severity: 'critical',
            message: `${data.label ?? ''}: 丢失 ${data.totalLost ?? 0} 包（丢包率 ${f2(data.lossRatePct)}%）`,
          });
        } else if ((data.reorderCount ?? 0) > 0) {
          issues.push({
            severity: 'info',
            message: `${data.label ?? ''}: 检测到 ${data.reorderCount} 个乱序包（未计入丢包）`,
          });
        }
      }
    }
  }

  // 时间戳连续性评估。文案面向非专业用户（"RTP 时间戳"直说成"声音时间
  // 轴"）；issue 附带 stream（对应 timestamp_continuity.streams 的键）与
  // explain（逐现象的直白解释），前端据此渲染可点击的逐包前后对照
  const tsContinuity = results.tsContinuity ?? {};
  for (const [label, data] of Object.entries(tsContinuity)) {
    const n = data.eventCount ?? 0;
    if (n === 0) continue;
    const parts: string[] = [];
    if (data.jumpCount) parts.push(`声音内容突然断开 ${data.jumpCount} 处`);
    if (data.backwardCount) parts.push(`声音时间往回走 ${data.backwardCount} 处（发送端时钟异常）`);
    if (data.reorderCount) parts.push(`数据包晚到/乱序 ${data.reorderCount} 处`);
    if (data.duplicateCount) parts.push(`同一时刻声音重复 ${data.duplicateCount} 处`);
    const gap = data.totalMediaGapMs ?? 0;
    let gapPart = '';
    let impact: string;
    if (gap >= 1) {
      gapPart = `累计缺少约 ${gapHuman(gap)}的声音内容，`;
      impact = gap < 50 ? '人耳基本听不出来' : gap < 300 ? '可能有轻微卡顿感' : '可能出现明显断音、吞字';
    } else {
      impact = '虽然声音内容没有缺失，但时间倒退/重复若频繁出现，可能引起卡顿或杂音';
    }
    issues.push({
      severity: data.backwardCount ? 'critical' : 'warning',
      message: `${prettyLabel(label)}: 这条流的声音时间轴异常：${parts.join('、')}，${gapPart}${impact}`,
      stream: label,
      explain: tsExplain(data, gap),
    });
  }
  if (Object.keys(tsContinuity).length > 0 &&
    Object.values(tsContinuity).every((d) => (d.eventCount ?? 0) === 0)) {
    okItems.push('所有流的声音时间轴连续（无断开/倒退/重复）');
  }

  // FS 媒体转发判定（音视频流是否真的经过 FS 转发 + 排查方向）
  const fsRelay = results.fsRelay ?? {};
  if (fsRelay.available) {
    const v = fsRelay.verdict;
    if (v === 'redirected' || v === 'no_relay') {
      issues.push({ severity: 'critical', message: `FS 媒体转发：${fsRelay.headline ?? ''}` });
    } else if (v === 'partial_uplink') {
      issues.push({ severity: 'warning', message: `FS 媒体转发：${fsRelay.headline ?? ''}` });
    } else if (v === 'relayed') {
      okItems.push('FS 媒体转发正常：各端媒体均经过 FS 中转');
    }
    for (const n of fsRelay.notes ?? []) {
      issues.push({ severity: 'warning', message: `FS 媒体转发：${n}` });
    }
  }

  // 无声诊断评估（directions 按主叫→坐席 / 坐席→主叫给出链路级判定）
  const audioHealth = results.audioHealth ?? {};
  if (audioHealth.available) {
    for (const d of audioHealth.directions ?? []) {
      const v = d.verdict;
      const label = `无声诊断·${d.label ?? ''}`;
      if (v === 'blocked' || v === 'no_source' || v === 'silent_source' || v === 'silent_path') {
        issues.push({ severity: 'critical', message: `${label}: ${d.verdictText ?? ''}` });
      } else if (v === 'unknown') {
        issues.push({
          severity: 'info',
          message: `${label}: 数据不足，无法判定（缺对应抓包点或编码不可解）`,
        });
      } else {
        okItems.push(`${label}: 链路正常，各段都有人声`);
      }
    }
  }

  // 分段延迟链路评估
  const delayChains = results.delayChains ?? {};
  if (delayChains.available) {
    for (const d of delayChains.directions ?? []) {
      if (d.verdict === 'high') {
        issues.push({
          severity: 'warning',
          message: `延迟链路·${d.label ?? ''}: ${d.verdictText ?? ''}`,
        });
      } else if (d.verdict === 'ok') {
        okItems.push(`延迟链路·${d.label ?? ''}: 各段延迟正常`);
      }
    }
    for (const r of delayChains.roundtrip ?? []) {
      if (r.status === 'high') {
        issues.push({
          severity: 'warning',
          message: `延迟链路·${r.pair ?? ''}: 往返 ${r.ms ?? 0}ms，链路整体偏慢`,
        });
      }
    }
  }

  // 音画质量分析（杂音/啸叫/削波破音/底噪 + 视频花屏风险）：
  // 每条流的 issues 逐条进结论并带上流名前缀，检测通过的流进 ok_items
  for (const [kind, entries] of [['audio', results.audioQuality ?? {}], ['video', results.videoQuality ?? {}]] as const) {
    for (const [label, q] of Object.entries(entries)) {
      for (const issue of q.issues ?? []) {
        issues.push({
          severity: asSeverity(issue.severity, 'warning'),
          message: `${prettyLabel(label)}: ${issue.message ?? ''}`,
        });
      }
      if (q.verdict === 'clean' || q.verdict === 'ok') {
        okItems.push(`${prettyLabel(label)}: ` +
          (kind === 'audio' ? '音质检测通过（无啸叫/杂音/削波）' : '视频流未发现花屏风险因素'));
      }
    }
  }

  // RTCP 接收端报告评估（RR 是接收端对收流质量的亲历上报）
  const rtcp = results.rtcp ?? {};
  for (const [label, entry] of Object.entries(rtcp)) {
    const rr = entry.rr;
    if (!rr) continue;
    const lostPct = rr.fractionLostPct ?? 0;
    if (lostPct > 2) {
      issues.push({
        severity: 'warning',
        message: `${prettyLabel(label)}: 接收端 RTCP RR 自报丢包 ${lostPct}%（累计 ${rr.cumLost ?? 0} 包）`,
      });
    } else {
      okItems.push(`${prettyLabel(label)}: 接收端 RR 丢包 ${lostPct}%`);
    }
  }
  if (results.rtcp != null && Object.keys(rtcp).length === 0) {
    issues.push({
      severity: 'info',
      message: '未捕获 RTCP 报告——接收端视角的丢包/抖动不可观测' +
        '（抓包点未覆盖 RTCP 端口，或终端未启用 RTCP）',
    });
  }

  // 根因分析（数据说明一并计入：抓包不完整本身就可能解释结论的缺口）
  const allIssues = [...dataNotes, ...issues];
  let rootCause: string;
  if (allIssues.length === 0) {
    rootCause = 'RTP 层面未发现明显问题。延迟可能来自应用层（抖动缓冲、音频设备、编码器缓冲），建议检查终端音频配置。';
  } else if (allIssues.some((i) => i.severity === 'critical')) {
    rootCause = 'RTP 层面发现严重问题，请检查 FS 配置与网络状况。';
  } else {
    rootCause = '发现轻微问题，建议持续观察，并考虑调整终端缓冲参数。';
  }

  return {
    issues: allIssues,
    okItems,
    rootCause,
    overall: allIssues.length === 0
      ? 'healthy'
      : allIssues.some((i) => i.severity === 'critical') ? 'critical' : 'warning',
  };
}

/** 生成完整的分析报告（移植自 Python generate_report）。 */
export function generateReport(results: ReportInput): Report {
  // 问题分类按所选媒体类型门控：只选音频时不出视频分类，反之亦然；
  // 未选中的键直接缺省，前端不渲染对应区块
  const mediaType = results.mediaType ?? 'audio';
  const report: Report = {
    metadata: {
      generatedAt: new Date().toISOString(),
      direction: results.direction ?? 'unknown',
      mediaType,
      numCaptures: results.numCaptures ?? 0,
      captureRoles: results.captureRoles ?? {},
    },
    topology: buildTopology(results),
    streams: buildStreamSummary(results),
    delay: buildDelaySummary(results),
    jitter: buildJitterSummary(results),
    packetLoss: buildLossSummary(results),
    timestampContinuity: buildTsSummary(results),
    clockOffset: buildClockSummary(results),
    audioHealth: results.audioHealth ?? null,
    delayChains: results.delayChains ?? null,
    rtcp: results.rtcp ?? null,
    mediaQuality: {
      audio: results.audioQuality ?? {},
      video: results.videoQuality ?? {},
    },
    conclusion: buildConclusion(results),
  };
  if (mediaType === 'audio' || mediaType === 'all') {
    // 声音问题分类：对照《声音问题种类》清单，把各检测器结论聚合为
    // "问题种类 + 用户听感词 + 排查方向"，供前端单独渲染
    report.problemClassification = classifyProblems(results);
  }
  if (mediaType === 'video' || mediaType === 'all') {
    // 视频问题分类：对照《视频问题种类》清单，同构聚合（视频流证据）
    report.videoProblemClassification = classifyVideoProblems(results);
  }
  return report;
}
