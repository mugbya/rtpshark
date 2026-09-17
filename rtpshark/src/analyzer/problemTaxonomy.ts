// 声音问题分类（problem_taxonomy.py 的 TS 移植）：把各检测器的原始结论
// 翻译成"用户听得懂的问题种类"。
//
// 对照《声音问题种类》清单（类别 / 用户听感词 / 工程术语 / 常见原因 /
// 验证方法 / P0~P3 优先级），并补充**可观测性**维度：抓包能直接确认的、
// 只能间接推断的、本质是声学/设备侧现象抓包看不到的，诚实区分三类，
// 避免"检测不到 = 没问题"的误导。
//
// classifyProblems() 消费各检测器的分析结果（此处以自定义最小输入接口
// 声明实际访问的字段，snake_case → camelCase，由管道层粘合）：
// 一个种类一条输出，附证据、用户听感词、排查方向与验证方法。同一问题被
// 多个检测器命中时合并为同一类下的多条证据。
//
// 视频问题的同构实现见 videoProblemTaxonomy.ts。

// ---------- 输出结构 ----------

export type Severity = 'critical' | 'warning' | 'info';

/** 问题分类表中的一行（名称 / 类别 / 工程术语 / 听感词 / 原因 / 验证） */
export interface TaxonomyEntry {
  name: string;
  category: string;
  term: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  feel: string[];
  description: string;
  causes: string[];
  verify: string[];
}

/** 抓包看不到的听感问题（只给人工验证方法） */
export interface UnobservableEntry {
  name: string;
  category: string;
  feel: string[];
  why: string;
  verify: string;
}

/** 一个问题种类的输出条目（固定字段 + 聚合证据） */
export interface ProblemEntry {
  id: string;
  name: string;
  category: string;
  term: string;
  priority: string;
  severity: string;
  feel: string[];
  description: string;
  evidence: string[];
  sources: string[];
  causes: string[];
  verify: string[];
}

export interface ProblemClassification {
  available: boolean;
  problems: ProblemEntry[];
  unobservable: UnobservableEntry[];
  summary: string;
  notes: string[];
}

// 证据严重级 → 展示排序
export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
const PRIORITY_RANK: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };

// ---------- 输入接口（只声明本模块实际访问的字段） ----------

export interface ClassifiedBucketsInput {
  audio?: Record<string, unknown>;
  video?: Record<string, unknown>;
  unknown?: Record<string, unknown>;
}

export interface AudioHealthDirectionInput {
  label?: string;
  verdict?: string;
  verdictText?: string;
}

export interface AudioHealthInput {
  available?: boolean;
  directions?: AudioHealthDirectionInput[];
}

export interface FsRelayDeviceCountersInput {
  pkts?: number;
}

export interface FsRelayDeviceLinkInput {
  audio?: FsRelayDeviceCountersInput;
  video?: FsRelayDeviceCountersInput;
}

export interface FsRelayDeviceInput {
  label?: string;
  ip?: string;
  uplink?: FsRelayDeviceLinkInput;
  downlink?: FsRelayDeviceLinkInput;
}

export interface FsRelayInput {
  available?: boolean;
  verdict?: string;
  headline?: string;
  devices?: FsRelayDeviceInput[];
}

export interface PacketLossEntryInput {
  label?: string;
  totalLost?: number;
  lossRatePct?: number;
  isClean?: boolean;
}

export interface RtcpRrInput {
  fractionLostPct?: number;
  cumLost?: number;
}

export interface RtcpFbInput {
  nack?: { requested?: number; packets?: number } | null;
  pli?: { count?: number } | null;
  fir?: { count?: number } | null;
}

export interface RtcpEntryInput {
  kind?: string;
  rr?: RtcpRrInput | null;
  fb?: RtcpFbInput | null;
}

export interface QualityIssueInput {
  kind?: string;
  severity?: string;
  message?: string;
}

export interface RtpIntegrityBriefInput {
  tsBackward?: number;
  tsDuplicate?: number;
}

export interface AudioQualityEntryInput {
  codec?: string;
  decodable?: boolean;
  rtpIntegrity?: RtpIntegrityBriefInput | null;
  issues?: QualityIssueInput[];
}

export interface TsContinuityEntryInput {
  mode?: string;
  totalMediaGapMs?: number;
  jumpCount?: number;
  backwardCount?: number;
  duplicateCount?: number;
  clockRate?: number | null;
  medianTsDelta?: number | null;
  packetCount?: number;
}

export interface FsDelayInput {
  count?: number;
  mean?: number;
  p95?: number;
}

export interface JitterEntryInput {
  std?: number;
}

export interface DelayChainDirectionInput {
  label?: string;
  verdict?: string;
  verdictText?: string;
}

export interface DelayChainRoundtripInput {
  pair?: string;
  status?: string;
  ms?: number;
}

export interface DelayChainsInput {
  available?: boolean;
  directions?: DelayChainDirectionInput[];
  roundtrip?: DelayChainRoundtripInput[];
}

export interface ProblemTaxonomyInput {
  classifiedStreams?: ClassifiedBucketsInput | null;
  audioHealth?: AudioHealthInput | null;
  fsRelay?: FsRelayInput | null;
  packetLoss?: Record<string, PacketLossEntryInput> | null;
  rtcp?: Record<string, RtcpEntryInput> | null;
  audioQuality?: Record<string, AudioQualityEntryInput> | null;
  tsContinuity?: Record<string, TsContinuityEntryInput> | null;
  fsDelay?: FsDelayInput | null;
  jitter?: Record<string, JitterEntryInput> | null;
  delayChains?: DelayChainsInput | null;
  mediaType?: string;
  checks?: { quality?: boolean } | null;
}

// ---------- 键形态兼容：int SSRC、'0x…' 十六进制串、展示标签 ----------
const SSRC_RE = /0x([0-9a-fA-F]+)/;

/** 从结果字典的键里取 SSRC 整数（兼容数字 / 十六进制串 / 纯数字串 / 展示标签） */
export function ssrcIntOf(key: string | number): number | null {
  if (typeof key === 'number') return key;
  const s = String(key);
  const m = s.match(SSRC_RE);
  if (m) return parseInt(m[1], 16);
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  return null;
}

/** 判定一个结果键（SSRC）属于 audio 还是 video。
 *  按 classifiedStreams 的分桶归属判别；缺数据时回退 audio（unknown 桶同按 audio）。 */
export function streamMediaKind(
  results: { classifiedStreams?: ClassifiedBucketsInput | null },
  key: string | number,
): 'audio' | 'video' {
  const ssrc = ssrcIntOf(key);
  const classified = results.classifiedStreams;
  if (ssrc !== null && classified) {
    if (classified.video && ssrc in classified.video) return 'video';
    if (classified.audio && ssrc in classified.audio) return 'audio';
  }
  return 'audio';
}

// 各检测器 issue kind → 问题种类 id（仅音画质量分析器的 kinds）
export const KIND_TO_PROBLEM: Record<string, string> = {
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
  // rtp_order 拆到 clock_anomaly / dup_audio，按 rtpIntegrity 字段区分
  // rtp_ok 是正常项，不进分类
};

// 丢包/断音类的优先级随严重度浮动（清单：严重断续 P1，机器人音/吞字 P2）
export const PRIORITY_BY_SEVERITY: Record<string, Record<string, string>> = {
  loss_artifact: { critical: 'P1', warning: 'P2', info: 'P2' },
  dropouts: { critical: 'P1', warning: 'P2', info: 'P3' },
  latency: { critical: 'P1', warning: 'P2', info: 'P3' },
};

// 抓包可直接观测/推断的问题种类。feel=用户听感词（清单"用户常说"列），
// description=种类描述，causes=常见原因/先查方向，verify=验证方法。
export const TAXONOMY: Record<string, TaxonomyEntry> = {
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

// 抓包层面无法直接确认的听感问题（清单里有、抓包测不到或不可靠），只给
// 出人工验证方法，避免"没报出来 = 没问题"的误导。
export const UNOBSERVABLE: UnobservableEntry[] = [
  {
    name: '风噪', category: '噪声', feel: ['呼呼的风声', '噗噗声'],
    why: '抓包只有编码后的字节流，无法区分"风吹麦克风"与一般环境噪声',
    verify: '户外/遮挡测试，换麦克风位置',
  },
  {
    name: '呼吸声 / 喷麦', category: '噪声', feel: ['呼气声很大', '噗——的喷麦声'],
    why: '近讲话学现象，谱形与人声重叠，抓包层无法判别',
    verify: '近讲测试，加防喷罩或开高通滤波（HPF）',
  },
  {
    name: '齿音刺耳', category: '噪声', feel: ['咝咝声刺耳'],
    why: '高频增益/EQ 问题，8k 窄带编码下高频已被截掉、抓包看不出来',
    verify: '录齿音对比，调高频 EQ',
  },
  {
    name: '忽大忽小（AGC 抽吸）', category: '音量', feel: ['声音一阵大一阵小'],
    why: 'AGC 动态行为需要电平波动统计，当前检测器暂未覆盖（可后续加入）',
    verify: '关 AGC 对比，看是否消失',
  },
  {
    name: '一动就断（接触不良）', category: '断续', feel: ['动一下线就没声'],
    why: '表现为整段流消失/长缺口，抓包无法与网络中断区分（FS 转发判定能排除转发侧）',
    verify: '摇动线材/接头测试，换线对比',
  },
  {
    name: '听到自己延迟（侧音/回声）', category: '回声', feel: ['听到自己的回声', '自己被延迟播放'],
    why: '需要上/下行音频相关性分析才能确认（可后续版本加入），单看时序不可靠',
    verify: '关侧音/AEC 对比，戴耳机确认是否消失',
  },
  {
    name: '双讲压制（半双工）', category: '双讲', feel: ['我一说话对方就断', '同时说话只剩一边'],
    why: 'AEC/降噪的双讲行为在单端抓包里无法与"对方本来就没说话"区分',
    verify: '双讲测试（双方同时说话），关 3A 对比',
  },
  {
    name: '特定 App 音频会话异常', category: '平台', feel: ['某个软件里才有问题'],
    why: '音频焦点/路由是终端操作系统行为，抓包不经过终端应用层',
    verify: '换 App 对比，查该 App 的音频权限与 SDK 版本',
  },
];

// 抓包里完全无声但"正常"的情况说明，避免把静音抑制误读成问题
export const NO_PROBLEM_NOTE =
  '以上未命中的听感问题不代表不存在——声学与设备侧现象抓包看不到，见"无法仅凭抓包确认"列表。';

/** 把累计媒体时间缺口换成人类可读单位（与报告层口径一致） */
export function gapHuman(gapMs: number): string {
  if (gapMs >= 60000) return `${(gapMs / 60000).toFixed(1)} 分钟`;
  if (gapMs >= 1000) return `${(gapMs / 1000).toFixed(1)} 秒`;
  return `${Math.round(gapMs)} 毫秒`;
}

/** 按问题 id 聚合证据；同一问题被多个检测器命中时合并为多条证据。
 *  taxonomy 缺省用音频清单，视频分类器传入 VIDEO_TAXONOMY 复用；
 *  priorityBySeverity 是"优先级随严重度浮动"的映射，缺省用音频表。 */
export class ProblemCollector {
  private readonly taxonomy: Record<string, TaxonomyEntry>;
  private readonly priorityBySeverity: Record<string, Record<string, string>>;
  private readonly found = new Map<string, {
    evidence: string[];
    sources: string[];
    severity: Severity;
  }>();

  constructor(
    taxonomy?: Record<string, TaxonomyEntry>,
    priorityBySeverity?: Record<string, Record<string, string>>,
  ) {
    this.taxonomy = taxonomy ?? TAXONOMY;
    this.priorityBySeverity = priorityBySeverity ?? PRIORITY_BY_SEVERITY;
  }

  get foundCount(): number {
    return this.found.size;
  }

  add(pid: string, evidence: string, severity: string = 'info', source = ''): void {
    const sev: Severity =
      severity === 'critical' || severity === 'warning' ? severity : 'info';
    let entry = this.found.get(pid);
    if (!entry) {
      entry = { evidence: [], sources: [], severity: 'info' };
      this.found.set(pid, entry);
    }
    if (!entry.evidence.includes(evidence)) entry.evidence.push(evidence);
    if (source && !entry.sources.includes(source)) entry.sources.push(source);
    if (SEVERITY_RANK[sev] < SEVERITY_RANK[entry.severity]) entry.severity = sev;
  }

  /** 按优先级 → 严重度输出问题条目（每种类的固定字段取自分类表） */
  output(): ProblemEntry[] {
    const sevRank = (s: string): number => SEVERITY_RANK[s as Severity] ?? SEVERITY_RANK.info;
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
      (sevRank(a.severity) - sevRank(b.severity)) ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return problems;
  }
}

/** 把分析结果归类到《声音问题种类》清单，输出面向用户的分类报告 */
export function classifyProblems(results: ProblemTaxonomyInput): ProblemClassification {
  const notes: string[] = [];
  let hasAudio = false;
  const col = new ProblemCollector();

  // —— 无声诊断：单通 / 无声（P0） ——
  const audioHealth = results.audioHealth;
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
  } else if (audioHealth !== null && audioHealth !== undefined) {
    notes.push('无声诊断不可用（未选中通话或缺对应抓包点），单通/无声只能靠流存在性间接判断');
  }

  // —— FS 媒体转发判定：改道 / 无上行同样是单通形态 ——
  const fsRelay = results.fsRelay;
  if (fsRelay?.available) {
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
    if (data.isClean !== false) continue;
    hasAudio = true;
    const sev = (data.lossRatePct ?? 0) >= 3 ? 'critical' : 'warning';
    col.add(
      'loss_artifact',
      `${data.label ?? ''}: 丢失 ${data.totalLost ?? 0} 包（丢包率 ${(data.lossRatePct ?? 0).toFixed(2)}%）`,
      sev,
      '丢包检测',
    );
  }

  // —— RTCP RR 自报丢包（接收端亲历视角；kind 缺省按音频，旧数据兼容） ——
  for (const [label, entry] of Object.entries(results.rtcp ?? {})) {
    if (entry.kind === 'video') continue;
    const rr = entry.rr;
    if (!rr) continue;
    const lostPct = rr.fractionLostPct ?? 0;
    if (lostPct > 2) {
      hasAudio = true;
      col.add(
        'loss_artifact',
        `${label}: 接收端 RTCP RR 自报丢包 ${lostPct}%（累计 ${rr.cumLost ?? 0} 包）`,
        'warning',
        'RTCP',
      );
    }
  }

  // —— 音画质量分析（DSP 检测 + RTP 秩序） ——
  for (const [label, q] of Object.entries(results.audioQuality ?? {})) {
    hasAudio = true;
    const integ = q.rtpIntegrity;
    if (integ?.tsBackward) {
      col.add(
        'clock_anomaly',
        `${label}: RTP 时间戳倒退 ${integ.tsBackward} 处——发送端时钟异常，播放重排会变调、忽快忽慢`,
        'critical',
        '音画质量',
      );
    }
    if (integ?.tsDuplicate) {
      col.add(
        'dup_audio',
        `${label}: RTP 时间戳重复 ${integ.tsDuplicate} 处——同一段声音会被播两遍`,
        'warning',
        '音画质量',
      );
    }
    for (const issue of q.issues ?? []) {
      const pid = KIND_TO_PROBLEM[issue.kind ?? ''];
      if (pid) {
        col.add(pid, `${label}: ${issue.message ?? ''}`, issue.severity ?? 'info', '音画质量');
      }
    }
    if (q.decodable) {
      const codec = q.codec ?? '';
      if (codec.includes('PCMU') || codec.includes('PCMA') || codec.includes('G.711')) {
        col.add(
          'narrowband',
          `${label}: 编码为 ${codec}（8kHz 窄带），3.4kHz 以上频段没有声音——听感发闷属编码特性，` +
            `若走蓝牙则很可能是 HFP/SCO 链路`,
          'info',
          '编码检查',
        );
      }
    }
  }

  // —— 时间戳连续性（发送端媒体时钟行为；frame 模式是视频流，跳过） ——
  for (const [label, data] of Object.entries(results.tsContinuity ?? {})) {
    if (data.mode === 'frame') continue;
    const gap = data.totalMediaGapMs ?? 0;
    if (data.jumpCount) {
      hasAudio = true;
      let sev: string;
      if (gap >= 300) sev = 'critical';
      else if (gap >= 50) sev = 'warning';
      else sev = 'info';
      col.add(
        'dropouts',
        `${label}: 声音内容断开 ${data.jumpCount} 处，累计缺少约 ${gapHuman(gap)}的声音` +
          (gap >= 50 ? '（含静音抑制的正常缺口，断点落在说话段才是问题）' : '（量很小，基本无感）'),
        sev,
        '时间戳连续性',
      );
    }
    if (data.backwardCount) {
      hasAudio = true;
      col.add(
        'clock_anomaly',
        `${label}: 声音时间往回走 ${data.backwardCount} 处（发送端时钟异常）`,
        'critical',
        '时间戳连续性',
      );
    }
    if (data.duplicateCount) {
      hasAudio = true;
      col.add(
        'dup_audio',
        `${label}: 同一时刻声音重复 ${data.duplicateCount} 处`,
        'warning',
        '时间戳连续性',
      );
    }
  }

  // —— 延迟 / 抖动 ——
  const fsDelay = results.fsDelay;
  if ((fsDelay?.count ?? 0) > 0) {
    if ((fsDelay?.mean ?? 0) >= 50) {
      col.add(
        'latency',
        `FS 内部处理延迟均值 ${(fsDelay?.mean ?? 0).toFixed(1)}ms（P95 ${(fsDelay?.p95 ?? 0).toFixed(1)}ms），明显偏高`,
        'critical',
        '延迟分析',
      );
    } else if ((fsDelay?.mean ?? 0) >= 20) {
      col.add(
        'latency',
        `FS 内部处理延迟均值 ${(fsDelay?.mean ?? 0).toFixed(1)}ms，偏高`,
        'warning',
        '延迟分析',
      );
    }
  }
  for (const [label, data] of Object.entries(results.jitter ?? {})) {
    if (streamMediaKind(results, label) === 'video') continue;
    if ((data.std ?? 0) > 10) {
      hasAudio = true;
      col.add(
        'latency',
        `${label}: 包间隔抖动偏大（标准差 ${(data.std ?? 0).toFixed(1)}ms）——播放缓冲压力大，会加剧断续`,
        'warning',
        '抖动分析',
      );
    }
  }
  const delayChains = results.delayChains;
  if (delayChains?.available) {
    for (const d of delayChains.directions ?? []) {
      if (d.verdict === 'high') {
        col.add('latency', `延迟链路·${d.label ?? ''}: ${d.verdictText ?? ''}`, 'warning', '延迟链路');
      }
    }
    for (const r of delayChains.roundtrip ?? []) {
      if (r.status === 'high') {
        col.add(
          'latency',
          `延迟链路·${r.pair ?? ''}: 往返 ${r.ms ?? 0}ms，链路整体偏慢`,
          'warning',
          '延迟链路',
        );
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
  if (!hasAudio && col.foundCount === 0) {
    notes.push('分析结果中没有音频流的检测数据，无法做声音问题分类');
  }

  const problems = col.output();
  // summary 只统计真正的问题（warning/critical）；info 级条目（如窄带编码
  // 特性说明）是解释性信息，不参与"发现问题"的计数，避免正常 G.711 通话
  // 被总结成"检出问题"
  const real = problems.filter((p) => p.severity !== 'info');
  let summary: string;
  if (real.length) {
    const worst = real[0];
    summary = `检出 ${real.length} 类声音问题，最需要先处理的是 ${worst.priority}·${worst.name}（${worst.category}）`;
  } else if (problems.length) {
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
    notes: notes.concat(problems.length ? [NO_PROBLEM_NOTE] : []),
  };
}
