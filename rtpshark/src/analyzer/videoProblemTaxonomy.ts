// 视频问题分类（video_problem_taxonomy.py 的 TS 移植）：把各检测器的原始
// 结论翻译成"用户看得懂的问题种类"。
//
// 对照《视频问题》清单（类别 / 用户观感词 / 工程术语 / 常见原因 / 关键指标 /
// P0~P3 优先级），与音频侧 problemTaxonomy.ts 同构。清单里几十行现象绝大多
// 数发生在终端侧（采集、渲染、屏幕、算法），抓包能验证的只有其中"媒体流
// 本身"的部分，因此同样按**可观测性**落位：
//
// - 抓包能直接确认的进 VIDEO_TAXONOMY：无画面/单通视频（转发路径断裂、
//   单向下发缺失）、花屏/绿屏（破损 NAL、解码错误）、弱网花屏（丢包及其
//   对下一个关键帧前的影响、NACK/RTCP RR 佐证）、关键帧问题（无 IDR、
//   PLI/FIR 频繁、首帧慢）、发送端时钟异常（时间戳倒退）、延迟/抖动、
//   帧率偏低（RTP 时间戳估算，变帧率编码仅供参考）；
// - 抓包看不到的进 VIDEO_UNOBSERVABLE：摄像头打不开/被占用/权限、模糊/
//   美颜类观感、偏色/曝光/闪烁、旋转/镜像/比例、音画不同步（需跨流
//   NTP 对时）、屏幕共享黑屏/无鼠标、发热降频/省电、机型兼容、前后摄
//   切换、虚拟背景/滤镜等前处理算法——只给人工验证方法。
//
// classifyVideoProblems() 与音频版共用 ProblemCollector 的聚合方式：一个
// 种类一条输出，同一问题被多个检测器命中时合并为多条证据；只统计属于
// 视频流的证据（packetLoss / jitter / rtcp 按流类别过滤）。
import type { ProblemClassification, TaxonomyEntry, UnobservableEntry } from './problemTaxonomy';
import {
  ProblemCollector,
  streamMediaKind,
} from './problemTaxonomy';
import type {
  FsRelayInput,
  PacketLossEntryInput,
  ProblemTaxonomyInput,
  QualityIssueInput,
  RtpIntegrityBriefInput,
  RtcpEntryInput,
  TsContinuityEntryInput,
} from './problemTaxonomy';

// 丢包/关键帧类优先级随严重度浮动（清单：弱网花屏 P1 起评，卡顿类 P2）
const VIDEO_PRIORITY_BY_SEVERITY: Record<string, Record<string, string>> = {
  no_video: { critical: 'P0', warning: 'P1' },
  video_loss: { critical: 'P1', warning: 'P2' },
  keyframe_issue: { critical: 'P0', warning: 'P1', info: 'P2' },
  video_clock_anomaly: { critical: 'P1', warning: 'P2' },
  video_latency: { critical: 'P1', warning: 'P2', info: 'P3' },
  low_fps: { warning: 'P2', info: 'P3' },
};

// 抓包可直接观测/推断的问题种类。feel=用户观感词（清单"用户常说"列），
// description=种类描述，causes=常见原因/先查方向，verify=验证方法。
export const VIDEO_TAXONOMY: Record<string, TaxonomyEntry> = {
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

// 抓包层面无法直接确认的观感问题（清单里有、抓包测不到），只给人工验证方法
export const VIDEO_UNOBSERVABLE: UnobservableEntry[] = [
  {
    name: '摄像头打不开 / 被占用 / 权限拒绝', category: '摄像头 / 采集',
    feel: ['摄像头打不开', '本地预览就全黑', '提示无权限'],
    why: '采集发生在终端本地，抓包只见"有没有视频 RTP"，分不清"没采集"还是"采集了没发"',
    verify: '看本地预览是否正常；系统相机能否打开；检查系统设置里的摄像头权限；关掉占用摄像头的其他应用',
  },
  {
    name: '前后摄切换失败', category: '摄像头 / 采集',
    feel: ['一切换前/后摄就黑屏或卡死'],
    why: '设备枚举与采集 Surface 重建是终端行为，媒体流上无痕迹',
    verify: '换设备对比复现；看切换瞬间终端日志',
  },
  {
    name: '模糊 / 分辨率低 / 磨皮发虚', category: '清晰度 / 画质',
    feel: ['模糊看不清', '分辨率低', '磨皮过度发虚'],
    why: '模糊是主观观感；分辨率/码率在码流元数据里，当前抓包分析未解析（后续可从 SPS 提取）',
    verify: '关美颜/滤镜对比；查终端分辨率与码率统计；确认对焦（AF）是否正常',
  },
  {
    name: '偏色 / 过暗 / 过曝 / 闪烁', category: '颜色 / 曝光',
    feel: ['脸色发绿/发紫', '逆光黑脸', '灯光下画面闪'],
    why: '色彩与曝光是像素级现象，RTP 抓包不逐像素可见（需解码出帧做图像分析，当前未做）',
    verify: '换光源/开抗闪烁（防工频干扰）对比；调曝光补偿/WDR；换设备对比',
  },
  {
    name: '旋转 / 镜像 / 拉伸 / 黑边', category: '方向 / 比例',
    feel: ['画面转了90度', '人是镜像的', '画面被压扁/有黑边'],
    why: '旋转由采集 metadata、镜像与拉伸由渲染端决定，编码数据本身不携带这些效果',
    verify: '换设备/换播放端对比；锁定屏幕方向重进；查渲染端宽高比与 letterbox 设置',
  },
  {
    name: '音画不同步', category: '音画同步',
    feel: ['口型对不上', '画面比声音慢/快'],
    why: '需要用 RTCP SR 的 NTP↔RTP 映射把音频与视频两路时钟对齐，中间抓包点时钟又与发送端不同步，offset 算不准',
    verify: '看终端 SDK 的 A/V offset 统计；换网络/设备对比；确认两端时钟源',
  },
  {
    name: '屏幕共享黑屏 / 看不到鼠标', category: '屏幕共享',
    feel: ['一共享就黑屏', '共享里没有鼠标'],
    why: 'DRM 保护、窗口/屏幕采集与光标捕获都是终端采集设置，抓包只见结果',
    verify: '换共享对象（窗口/标签页）对比；关硬件加速；确认采集权限与光标捕获开关',
  },
  {
    name: '越用越卡 / 发热掉帧 / 省电模式', category: '性能 / 设备',
    feel: ['越用越卡', '机身发烫后掉帧', '开省电就卡'],
    why: '温控降频是终端系统行为，媒体流上只见"帧变少了"，分不清弱网还是降频',
    verify: '关省电模式、散热后复测；看终端 CPU/GPU 频率与温度',
  },
  {
    name: '特定机型异常', category: '性能 / 设备',
    feel: ['只有某款设备有问题'],
    why: '硬编硬解兼容性要看终端解码器日志，码流层面大多正常',
    verify: '换机型复测；关硬件编解码对比',
  },
  {
    name: '美颜 / 虚拟背景 / 滤镜类前处理异常', category: '前处理 / 算法',
    feel: ['虚拟背景边缘闪烁', '背景虚化穿帮', '滤镜偏色'],
    why: '前处理发生在编码之前，抓包拿到的是处理后的码流，无法还原算法行为',
    verify: '逐项关闭美颜/虚拟背景/滤镜/降噪/防抖对比',
  },
];

const NO_VIDEO_PROBLEM_NOTE =
  '以上未命中的观感问题不代表不存在——采集、渲染、算法侧现象抓包看不到，见"无法仅凭抓包确认"列表。';

// PLI/FIR 请求关键帧次数达到该值才报（偶发一两次属解码器正常初始化）
export const PLI_STORM_MIN = 3;
// 视频丢包率 ≥1% 即按"花到关键帧"评估（视频对丢包远比音频敏感）
export const VIDEO_LOSS_CRITICAL_PCT = 1.0;

// ---------- 输入接口（只声明本模块实际访问的字段） ----------

export interface VideoQualityEntryInput {
  rtpIntegrity?: RtpIntegrityBriefInput | null;
  issues?: QualityIssueInput[];
}

export interface VideoProblemTaxonomyInput extends ProblemTaxonomyInput {
  videoQuality?: Record<string, VideoQualityEntryInput> | null;
}

// 各检测器 issue kind → 问题种类 id：
// broken_nal/decode_errors → 花屏；video_loss/no_idr/idr_gap → 各归其类；
// rtp_order 不经 kind 映射（与音频分类器同构，直接读 rtpIntegrity）
const VQ_KIND_MAP: Record<string, string> = {
  broken_nal: 'corrupt_video',
  decode_errors: 'corrupt_video',
  video_loss: 'video_loss',
  no_idr: 'keyframe_issue',
  idr_gap: 'keyframe_issue',
};

/** 把分析结果归类到《视频问题》清单，输出面向用户的分类报告 */
export function classifyVideoProblems(results: VideoProblemTaxonomyInput): ProblemClassification {
  const notes: string[] = [];
  const videoBuckets = results.classifiedStreams?.video ?? {};
  const hasVideo =
    Object.keys(videoBuckets).length > 0 ||
    Object.keys(results.videoQuality ?? {}).length > 0;
  const col = new ProblemCollector(VIDEO_TAXONOMY, VIDEO_PRIORITY_BY_SEVERITY);

  // —— FS 媒体转发判定：改道 / 无上行时视频同样断流（P0 形态） ——
  const fsRelay: FsRelayInput = results.fsRelay ?? {};
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
    if (relayVerdict !== 'redirected' && relayDevices.length) {
      for (const upDev of relayDevices) {
        if ((upDev.uplink?.video?.pkts ?? 0) <= 0) continue;
        for (const downDev of relayDevices) {
          if (downDev.ip === upDev.ip) continue;
          if (
            (downDev.downlink?.video?.pkts ?? 0) <= 0 &&
            (downDev.uplink?.audio?.pkts ?? 0) > 0
          ) {
            const upLabel = upDev.label ?? '';
            const downLabel = downDev.label ?? '';
            col.add(
              'no_video',
              `${upLabel} 上行了视频（${upDev.uplink?.video?.pkts ?? 0} 包），但 FS ` +
                `从未向 ${downLabel} 下发过视频——${downLabel} 侧看不到` +
                `${upLabel} 的画面（单通视频）`,
              'critical',
              'FS 转发判定',
            );
          }
        }
      }
    }
  }

  // —— 音画质量分析（花屏 / 解码 / 时钟） ——
  for (const [label, q] of Object.entries(results.videoQuality ?? {})) {
    const integ = q.rtpIntegrity;
    if (integ?.tsBackward) {
      col.add(
        'video_clock_anomaly',
        `${label}: RTP 时间戳倒退 ${integ.tsBackward} 处——发送端时钟异常，帧序重排会错位，花屏/冻结风险高`,
        'critical',
        '音画质量',
      );
    }
    for (const issue of q.issues ?? []) {
      const pid = VQ_KIND_MAP[issue.kind ?? ''];
      if (pid) {
        col.add(pid, `${label}: ${issue.message ?? ''}`, issue.severity ?? 'info', '音画质量');
      }
    }
  }

  // —— 流级丢包（只认视频流；视频质量分析已覆盖的流不重复报） ——
  const vqLabels = new Set(Object.keys(results.videoQuality ?? {}));
  for (const [key, data] of Object.entries(results.packetLoss ?? {})) {
    if (streamMediaKind(results, key) !== 'video') continue;
    const lossData: PacketLossEntryInput = data;
    if (lossData.isClean !== false || (lossData.label !== undefined && vqLabels.has(lossData.label))) {
      continue;
    }
    const sev =
      (lossData.lossRatePct ?? 0) >= VIDEO_LOSS_CRITICAL_PCT ? 'critical' : 'warning';
    col.add(
      'video_loss',
      `${lossData.label ?? ''}: 丢失 ${lossData.totalLost ?? 0} 包` +
        `（丢包率 ${(lossData.lossRatePct ?? 0).toFixed(2)}%）——丢包处画面会` +
        `花屏直到下一个关键帧刷新`,
      sev,
      '丢包检测',
    );
  }

  // —— RTCP：接收端自报丢包 / NACK 重传 / PLI-FIR 关键帧请求 ——
  for (const [label, entry] of Object.entries(results.rtcp ?? {})) {
    const rtcpEntry: RtcpEntryInput = entry;
    if (rtcpEntry.kind !== 'video') continue;
    const rr = rtcpEntry.rr;
    if (rr && (rr.fractionLostPct ?? 0) > 0.5) {
      col.add(
        'video_loss',
        `${label}: 接收端 RTCP RR 自报丢包 ${rr.fractionLostPct}%（累计 ${rr.cumLost ?? 0} 包）`,
        'warning',
        'RTCP',
      );
    }
    const fb = rtcpEntry.fb ?? {};
    const nack = fb.nack;
    if (nack && nack.requested) {
      col.add(
        'video_loss',
        `${label}: 接收端 NACK 指名重传 ${nack.requested} 个包（${nack.packets ?? 0} 次）——接收端确实在丢包并补救`,
        'warning',
        'RTCP',
      );
    }
    const pli = fb.pli;
    const fir = fb.fir;
    const reqCnt = (pli?.count ?? 0) + (fir?.count ?? 0);
    if (reqCnt >= PLI_STORM_MIN) {
      col.add(
        'keyframe_issue',
        `${label}: 接收端请求关键帧 ${reqCnt} 次（PLI ${pli?.count ?? 0} / FIR ${fir?.count ?? 0}）` +
          `——解码层反复在等参考帧，对应画面在花屏或停住`,
        'warning',
        'RTCP',
      );
    }
  }

  // —— 时间戳连续性（只看 frame 模式 = 视频流）+ 帧率估算 ——
  for (const [label, data] of Object.entries(results.tsContinuity ?? {})) {
    const tsData: TsContinuityEntryInput = data;
    if (tsData.mode !== 'frame') continue;
    if (tsData.backwardCount) {
      col.add(
        'video_clock_anomaly',
        `${label}: 视频时间戳往回走 ${tsData.backwardCount} 处（发送端时钟异常）`,
        'critical',
        '时间戳连续性',
      );
    }
    const rate = tsData.clockRate;
    const medianDelta = tsData.medianTsDelta ?? 0;
    if (rate && medianDelta > 0 && (tsData.packetCount ?? 0) >= 100) {
      const fps = rate / medianDelta;
      if (fps < 10) {
        col.add(
          'low_fps',
          `${label}: 估算帧率仅 ${fps.toFixed(1)} fps（按 RTP 时间戳估算；变帧率编码如屏幕共享会天然偏低，仅供参考）`,
          'warning',
          '时间戳连续性',
        );
      } else if (fps < 15) {
        col.add(
          'low_fps',
          `${label}: 估算帧率约 ${fps.toFixed(1)} fps，偏低（变帧率编码下仅供参考）`,
          'info',
          '时间戳连续性',
        );
      }
    }
  }

  // —— 延迟 / 抖动（只认视频流） ——
  const fsDelay = results.fsDelay;
  if ((fsDelay?.count ?? 0) > 0) {
    if ((fsDelay?.mean ?? 0) >= 50) {
      col.add(
        'video_latency',
        `FS 内部处理延迟均值 ${(fsDelay?.mean ?? 0).toFixed(1)}ms（P95 ${(fsDelay?.p95 ?? 0).toFixed(1)}ms），视频画面同样被拖慢`,
        'critical',
        '延迟分析',
      );
    } else if ((fsDelay?.mean ?? 0) >= 20) {
      col.add(
        'video_latency',
        `FS 内部处理延迟均值 ${(fsDelay?.mean ?? 0).toFixed(1)}ms，偏高`,
        'warning',
        '延迟分析',
      );
    }
  }
  for (const [label, data] of Object.entries(results.jitter ?? {})) {
    if (streamMediaKind(results, label) !== 'video') continue;
    if ((data.std ?? 0) > 10) {
      col.add(
        'video_latency',
        `${label}: 包间隔抖动偏大（标准差 ${(data.std ?? 0).toFixed(1)}ms）——解码缓冲压力大，表现为画面一顿一顿`,
        'warning',
        '抖动分析',
      );
    }
  }

  // —— 适用范围与说明 ——
  if (!Object.keys(videoBuckets).length && !Object.keys(results.videoQuality ?? {}).length) {
    notes.push(
      '抓包里没有视频流的检测数据：若该通话本应有视频（用户报"没画面"），先查 SDP 视频协商、' +
        '摄像头权限与占用——属于终端/协商侧，抓包层面只能确认"没有视频 RTP"',
    );
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
  if (real.length) {
    const worst = real[0];
    summary = `检出 ${real.length} 类视频问题，最需要先处理的是 ${worst.priority}·${worst.name}（${worst.category}）`;
  } else if (problems.length) {
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
    notes: notes.concat(problems.length ? [NO_VIDEO_PROBLEM_NOTE] : []),
  };
}
