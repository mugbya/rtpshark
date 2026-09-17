# RTPShark · RTP 音视频流分析（桌面版）

VoIP 通话 RTP 音视频流分析桌面应用（Tauri 2 + React 19 + TypeScript）。基于
[rtp-stream-analyzer](https://github.com/mugbya/rtp-stream-analyzer)（Python/Flask Web 版）
的完整 TypeScript 移植：加载抓包文件（pcap/pcapng），自动检测**通话数量与抓包完整性**，
分析**延迟、抖动、丢包、时间戳连续性**，检测**杂音/啸叫/削波/花屏**类音画异常，
并从 RTP 流**重建音频/视频供回放**。

## 与 Web 版的差异

| 能力 | Web 版 | 桌面版 |
|---|---|---|
| 分析引擎 | Python + scapy | TypeScript 移植，运行于内置 Web Worker（无需安装 Python） |
| 图表 | matplotlib 9 面板 PNG | 无（以统计表格 + 文字报告呈现分析结果） |
| 音频回放 | 服务端 WAV 文件 | G.711 解码后应用内直接播放 / 下载 WAV |
| 视频回放 | ffmpeg 转 MP4 | H.264 去分片后应用内封装 MP4 播放（失败时下载裸流 .h264） |
| ffmpeg 解码校验 | 有（可选） | 无（保留 RTP 层证据：丢包→花屏映射、破损 NAL、关键帧间隔） |
| 数据留存 | 2 小时自动清理 | 全程在内存中，关闭窗口即释放 |

## 功能（同 Web 版）

1. **通话检测与完整性标注**：按双向端口对 + 时间重叠聚类通话、跨抓包按 SSRC 合并、
   INVITE/BYE 完整性判断、传错文件提醒、抓包截短/文件尾损坏提示、SIP 信令阶梯图
2. **延迟 / 抖动 / 丢包**：FS 内部处理延迟、跨抓包传输延迟（自动时钟偏移修正）、
   端到端估算、包间隔统计（均值/中位数/P95/P99）、序号连续性丢包检测
3. **音视频重建与回放**：G.711 PCMU/PCMA → WAV（丢包补静音，标注谁到谁）；H.264 → MP4/裸流
4. **音画质量分析**：啸叫/低频嗡声/削波/爆点/底噪/音量（G.711 解码后 DSP）、
   视频花屏风险（丢包→距下个关键帧时长、破损 NAL 计数、关键帧间隔）
5. **单端到三端自适应**：1~3 个抓包（终端/FS/坐席）任意组合，不可测项自动置灰

## 使用流程

1. **选择抓包文件**：为 主叫端（终端）/ 服务端（FS）/ 被叫端（坐席）任选 1~3 个 pcap/pcapng
2. **上传并识别**：查看服务器 IP、音视频流数量、通话列表（点开可看判断依据与信令阶梯图）
3. **选择分析参数**：通话、媒体类型（音频/视频/全部）、是否测延迟
4. **查看结果**：摘要卡片 → 音视频回放 → 详细报告

## 开发

```bash
pnpm install
pnpm tauri dev    # 桌面应用开发模式
pnpm build        # 前端构建（tsc + vite build）
pnpm tauri build  # 打包桌面应用
```

## 代码结构

```
src/
├── analyzer/                # 分析引擎（全部在 Web Worker 中运行）
│   ├── types.ts             # 共享类型
│   ├── captureIntegrity.ts  # pcap/pcapng 读取 + 截短/尾损坏检测
│   ├── rtpParser.ts         # RTP 头 / SIP / SDP 解析、IP 分片重组
│   ├── rtcpParser.ts        # RTCP SR/RR/NACK/PLI/FIR
│   ├── streamClassifier.ts  # 音视频流分类、服务器 IP 识别
│   ├── callDetector.ts      # 通话分组 + 完整性 + FS 转发判定
│   ├── jitterAnalyzer.ts    # 包间隔/抖动
│   ├── packetLoss.ts        # 丢包检测
│   ├── tsContinuity.ts      # 时间戳连续性
│   ├── delayAnalyzer.ts     # FS 内部 / 跨抓包延迟、时钟偏移
│   ├── delayChains.ts       # 分段延迟链路
│   ├── silenceAnalyzer.ts   # 无声诊断
│   ├── mediaExtractor.ts    # G.711→WAV、H.264→MP4（内存）
│   ├── qualityAnalyzer.ts   # 杂音/啸叫/削波/花屏检测
│   ├── problemTaxonomy.ts   # 声音问题分类
│   ├── reporter.ts          # 汇总报告
│   ├── pipeline.ts          # 上传/分析两阶段管道（对应 app.py）
│   ├── worker.ts            # Worker 入口
│   └── workerClient.ts      # 主线程封装
├── ui/                      # 结果视图 / 回放 / 报告 / SIP 阶梯图
└── App.tsx                  # 五步式主流程
```
