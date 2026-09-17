// 结果视图：摘要卡片 → 音视频回放 → 详细报告
import { useEffect, useMemo } from "react";
import type { AnalyzeOutput } from "../analyzer/pipeline";
import type { UploadResult } from "../analyzer/types";

export function ResultsView({
  output,
  mediaType,
  checkDelay,
}: {
  output: AnalyzeOutput;
  upload?: UploadResult;
  mediaType: string;
  checkDelay: boolean;
}) {
  const results = output.results;

  // 媒体 Blob URL：worker 传回字节，主线程生成可播放的 ObjectURL
  const mediaUrls = useMemo(() => {
    const map = new Map<string, string>();
    for (const e of [...output.media.audio, ...output.media.video]) {
      const bytes =
        e.direction !== undefined && e.wavBytes
          ? e.wavBytes
          : e.mp4Bytes || e.h264Bytes;
      if (!bytes) continue;
      const mime = e.wavBytes
        ? "audio/wav"
        : e.mp4Bytes
          ? "video/mp4"
          : "video/mp4"; // h264 裸流浏览器不解，统一给 mp4（有则播，无则只给下载）
      map.set(e.key, URL.createObjectURL(new Blob([bytes as BlobPart], { type: mime })));
    }
    return map;
  }, [output]);

  useEffect(() => {
    return () => {
      for (const url of mediaUrls.values()) URL.revokeObjectURL(url);
    };
  }, [mediaUrls]);

  const fsDelay = results.fsDelay as { mean?: number; p95?: number; count?: number } | null;
  const lossValues = Object.values(results.packetLoss || {}) as { isClean?: boolean }[];
  const tsValues = Object.values(results.tsContinuity || {}) as { eventCount?: number }[];
  const qualityEntries = [
    ...Object.values(results.audioQuality || {}),
    ...Object.values(results.videoQuality || {}),
  ] as { verdict?: string }[];

  const mediaQuality = {
    checked: qualityEntries.some((e) => e.verdict),
    clean:
      qualityEntries.length > 0 &&
      qualityEntries.every((e) => !e.verdict || ["clean", "ok"].includes(e.verdict)),
  };

  const lossClean = lossValues.every((d) => d.isClean !== false);
  const tsClean = tsValues.every((d) => (d.eventCount || 0) === 0);
  const overall = (results.report as { conclusion?: { overall?: string } })?.conclusion?.overall;

  return (
    <>
      {/* Step 4: 分析结果 */}
      <div className="card">
        <div className="card-header step-4">④ 分析结果{results.callId ? ` · 通话 ${results.callId}` : ""}</div>
        <div className="card-body">
          {results.captureIntegrity &&
            Object.keys(results.captureIntegrity).length > 0 && (
              <div className="banner warn">
                ⚠️ 部分抓包文件存在完整性问题，相关统计可能受影响。
              </div>
            )}

          <div className="summary-cards">
            <div className="summary-card">
              <div className="k">总体结论</div>
              <div className="v">{overallLabel(overall)}</div>
            </div>
            <div className="summary-card">
              <div className="k">FS 内部延迟 均值</div>
              <div className="v">
                {checkDelay && fsDelay?.mean != null ? `${fsDelay.mean.toFixed(1)} ms` : "未测量"}
              </div>
            </div>
            <div className="summary-card">
              <div className="k">FS 内部延迟 P95</div>
              <div className="v">
                {checkDelay && fsDelay?.p95 != null ? `${fsDelay.p95.toFixed(1)} ms` : "未测量"}
              </div>
            </div>
            <div className="summary-card">
              <div className="k">抖动分析流数</div>
              <div className="v">{Object.keys(results.jitter || {}).length}</div>
            </div>
            <div className="summary-card">
              <div className="k">丢包</div>
              <div className="v">{lossClean ? "正常" : "有丢包"}</div>
            </div>
            <div className="summary-card">
              <div className="k">时间戳连续性</div>
              <div className="v">{tsClean ? "正常" : "有异常"}</div>
            </div>
            <div className="summary-card">
              <div className="k">音画质量</div>
              <div className="v">
                {mediaQuality.checked ? (mediaQuality.clean ? "正常" : "有异常") : "未检测"}
              </div>
            </div>
            {results.clockInfo?.warning != null && (
              <div className="summary-card">
                <div className="k">时钟偏移</div>
                <div className="v" style={{ color: "var(--warn)" }}>有警告</div>
              </div>
            )}
          </div>

          <p className="small muted mt-2">
            分析范围: {mediaTypeLabel(mediaType)} · 延迟测量: {checkDelay ? "开启" : "关闭"} · 抓包点数: {results.numCaptures}
          </p>
        </div>
      </div>

      {/* Step 5: 音视频回放 */}
      {(output.media.audio.length > 0 || output.media.video.length > 0) && (
        <div className="card">
          <div className="card-header step-5">⑤ 音视频回放</div>
          <div className="card-body">
            <p className="muted small mb-2">
              从 RTP 流重建的音频/视频。按抓包文件分组，<strong>呼出</strong>为该端发送的媒体，<strong>呼入</strong>为该端接收的媒体。
            </p>
            {output.media.parties && (output.media.parties as unknown[]).length > 0 && (
              <p className="small mb-2">
                通话拓扑：{(output.media.parties as string[]).join(" ↔ ")}
              </p>
            )}

            {groupEntries(output.media.audio).map(([role, entries]) => (
              <div key={role} className="media-group">
                <h4>{role}</h4>
                {entries.map((e) => (
                  <div key={e.key} className="media-item">
                    <div className="meta">
                      <div>
                        <span className={`badge ${e.direction === "outbound" ? "green" : "blue"}`}>
                          {e.direction === "outbound" ? "呼出" : "呼入"}
                        </span>
                        <span className="badge gray">{e.ssrc}</span>
                        {e.label && <span className="badge purple">{e.label}</span>}
                      </div>
                      {e.durationSec != null && (
                        <div className="small muted">时长 ≈ {e.durationSec.toFixed(1)} 秒</div>
                      )}
                    </div>
                    {e.wavBytes && mediaUrls.get(e.key) && (
                      <audio controls src={mediaUrls.get(e.key)} />
                    )}
                    <DownloadBtn bytes={e.wavBytes || e.mp4Bytes || e.h264Bytes} name={`${role}_${e.direction}_${e.ssrc}.${e.wavBytes ? "wav" : e.mp4Bytes ? "mp4" : "h264"}`} />
                  </div>
                ))}
              </div>
            ))}

            {output.media.video.length > 0 && (
              <div className="media-group">
                <h4>视频流</h4>
                {output.media.video.map((e) => (
                  <div key={e.key} className="media-item">
                    <div className="meta">
                      <div>
                        <span className={`badge ${e.direction === "outbound" ? "green" : "blue"}`}>
                          {e.direction === "outbound" ? "呼出" : "呼入"}
                        </span>
                        <span className="badge gray">{e.ssrc}</span>
                        {e.label && <span className="badge purple">{e.label}</span>}
                      </div>
                    </div>
                    {e.mp4Bytes && mediaUrls.get(e.key) && (
                      <video controls src={mediaUrls.get(e.key)} width={320} />
                    )}
                    <DownloadBtn
                      bytes={e.mp4Bytes || e.h264Bytes}
                      name={`video_${e.direction}_${e.ssrc}.${e.mp4Bytes ? "mp4" : "h264"}`}
                    />
                  </div>
                ))}
              </div>
            )}

            {output.media.unsupported &&
              (output.media.unsupported as { label?: string; codec?: string }[]).length > 0 && (
                <div className="banner info">
                  以下流的编码暂不支持重建：
                  {(output.media.unsupported as { label?: string; codec?: string }[])
                    .map((u) => `${u.label || ""}（${u.codec || "未知编码"}）`)
                    .join("、")}
                </div>
              )}
          </div>
        </div>
      )}

      {/* 详细报告 */}
      <Suspense fallback={<div className="status-line">报告生成中…</div>}>
        <ReportLazy report={results.report as Report} />
      </Suspense>
    </>
  );
}

import { lazy, Suspense } from "react";
import type { Report } from "../analyzer/reporter";
const ReportLazy = lazy(() =>
  import("./ReportView").then((m) => ({ default: m.ReportView })),
);

function overallLabel(v?: string | null): string {
  if (!v) return "—";
  const map: Record<string, string> = {
    good: "良好",
    ok: "正常",
    normal: "正常",
    warn: "有警告",
    warning: "有警告",
    bad: "有问题",
    critical: "严重",
  };
  return map[v.toLowerCase?.() || v] || v;
}

function mediaTypeLabel(v: string): string {
  return v === "audio" ? "仅音频" : v === "video" ? "仅视频" : "音视频";
}

function groupEntries(
  entries: { key: string; role: string; ssrc: string; direction: string; label: string; durationSec?: number; wavBytes?: Uint8Array; mp4Bytes?: Uint8Array; h264Bytes?: Uint8Array }[],
): [string, typeof entries][] {
  const groups = new Map<string, typeof entries>();
  for (const e of entries) {
    const list = groups.get(e.role) || [];
    list.push(e);
    groups.set(e.role, list);
  }
  return [...groups.entries()];
}

function DownloadBtn({
  bytes,
  name,
}: {
  bytes?: Uint8Array;
  name: string;
}) {
  if (!bytes) return null;
  return (
    <a
      className="btn"
      style={{ fontSize: 12 }}
      download={name}
      href={URL.createObjectURL(new Blob([bytes as BlobPart]))}
      onClick={(ev) => {
        // 用完即弃，避免累积 URL
        setTimeout(() => URL.revokeObjectURL(ev.currentTarget.href), 10_000);
      }}
    >
      下载
    </a>
  );
}
