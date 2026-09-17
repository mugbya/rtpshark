// 详细报告渲染（对应 Python generate_report 输出的 Report 结构）
import { lazy, Suspense } from "react";
import type { Report } from "../analyzer/reporter";

const OVERALL: Record<string, { text: string; cls: string }> = {
  healthy: { text: "✅ 总体正常", cls: "green" },
  warning: { text: "⚠️ 有警告", cls: "yellow" },
  critical: { text: "❌ 有严重问题", cls: "red" },
};

const SEV_CLS: Record<string, string> = {
  critical: "critical",
  warning: "warning",
  info: "info",
};

const ProblemCards = lazy(() =>
  import("./ProblemCards").then((m) => ({ default: m.ProblemCards })),
);

export function ReportView({ report }: { report: Report }) {
  if (!report) return null;
  const overall = OVERALL[report.conclusion?.overall] || {
    text: report.conclusion?.overall,
    cls: "gray",
  };

  return (
    <div className="card">
      <div className="card-header step-4">⑥ 详细报告</div>
      <div className="card-body">
        {/* 结论 */}
        <div className="report-section">
          <h3>结论 {overall && <span className={`badge ${overall.cls}`}>{overall.text}</span>}</h3>
          <p className="small">{report.conclusion?.rootCause}</p>
          {report.conclusion?.issues?.map((iss, i) => (
            <div key={i} className={`report-item ${SEV_CLS[iss.severity] || ""}`}>
              <span className="title">[{iss.severity === "critical" ? "严重" : iss.severity === "warning" ? "警告" : "提示"}]</span>{" "}
              {iss.message}
              {iss.stream && <span className="muted">（{iss.stream}）</span>}
              {iss.explain && <div className="small muted">{iss.explain}</div>}
            </div>
          ))}
          {report.conclusion?.okItems?.length ? (
            <details className="block mt-2">
              <summary className="small">正常项（{report.conclusion.okItems.length}）</summary>
              {report.conclusion.okItems.map((ok, i) => (
                <div key={i} className="report-item ok small">✓ {ok}</div>
              ))}
            </details>
          ) : null}
        </div>

        {/* 声音/视频问题分类卡片 */}
        {(report.problemClassification || report.videoProblemClassification) && (
          <div className="report-section">
            <h3>声音/画面问题分类</h3>
            <Suspense fallback={<p className="small muted">分类卡片加载中…</p>}>
              <ProblemCards
                audio={report.problemClassification}
                video={report.videoProblemClassification}
              />
            </Suspense>
          </div>
        )}

        {/* 延迟 */}
        <div className="report-section">
          <h3>延迟分析</h3>
          <DelayBlock report={report} />
        </div>

        {/* 抖动 */}
        <div className="report-section">
          <h3>抖动分析</h3>
          <table className="plain">
            <thead>
              <tr>
                <th>流</th><th>均值 ms</th><th>中位数 ms</th><th>P95 ms</th><th>标准差</th><th>异常间隔</th><th>理想间隔 ms</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(report.jitter || {}).map(([label, j]) => (
                <tr key={label}>
                  <td>{label}</td>
                  <td>{fmt(j.mean)}</td><td>{fmt(j.median)}</td><td>{fmt(j.p95)}</td>
                  <td>{fmt(j.std)}</td>
                  <td>{j.abnormalCount}</td>
                  <td>{fmt(j.expectedInterval)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* 丢包 */}
        <div className="report-section">
          <h3>丢包分析</h3>
          <table className="plain">
            <thead>
              <tr>
                <th>流</th><th>收包</th><th>丢包</th><th>丢包率 %</th><th>乱序</th><th>结论</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(report.packetLoss || {}).map(([label, l]) => (
                <tr key={label}>
                  <td>{l.label || label}</td>
                  <td>{l.totalPackets}</td>
                  <td>{l.totalLost}</td>
                  <td>{fmt(l.lossRatePct)}</td>
                  <td>{l.reorderCount}</td>
                  <td>{l.isClean ? "✅ 无丢包" : "❌ 有丢包"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* 时间戳连续性 */}
        <div className="report-section">
          <h3>时间戳连续性</h3>
          {Object.entries(report.timestampContinuity?.streams || {}).length === 0 && (
            <p className="small muted">无数据。</p>
          )}
          {Object.entries(report.timestampContinuity?.streams || {}).map(([label, t]) => (
            <div key={label} className="report-item small">
              <span className="title">{label}</span>{" "}
              {t.isContinuous ? (
                <span className="badge green">连续</span>
              ) : (
                <span className="badge red">
                  {t.eventCount} 个异常（跳变 {t.jumpCount} / 倒退 {t.backwardCount} / 乱序 {t.reorderCount} / 重复 {t.duplicateCount}）
                </span>
              )}
              <span className="muted">
                {" "}· {t.packetCount} 包 · PT {t.pt ?? "—"} · 时钟 {t.clockRate ?? "—"}
                {t.packetDurationMs != null && ` · 每包 ≈ ${fmt(t.packetDurationMs)} ms`}
                {t.totalMediaGapMs > 0 && ` · 媒体时间缺口 ${fmt(t.totalMediaGapMs)} ms`}
              </span>
            </div>
          ))}
        </div>

        {/* 音画质量 */}
        <div className="report-section">
          <h3>音画质量分析</h3>
          <QualityBlock entries={report.mediaQuality?.audio} kind="音频" />
          <QualityBlock entries={report.mediaQuality?.video} kind="视频" />
        </div>

        {/* 无声诊断 / 延迟链路 / FS 转发 */}
        {report.audioHealth && (
          <div className="report-section">
            <h3>无声诊断</h3>
            <pre className="small" style={{ whiteSpace: "pre-wrap" }}>
              {JSON.stringify(report.audioHealth, null, 2)}
            </pre>
          </div>
        )}
        {report.delayChains && (
          <div className="report-section">
            <h3>分段延迟链路</h3>
            <pre className="small" style={{ whiteSpace: "pre-wrap" }}>
              {JSON.stringify(report.delayChains, null, 2)}
            </pre>
          </div>
        )}
        {report.rtcp && Object.keys(report.rtcp).length > 0 && (
          <div className="report-section">
            <h3>RTCP 收发报告</h3>
            <table className="plain">
              <thead>
                <tr><th>流</th><th>种类</th><th>对端上报丢包率 %</th><th>累计丢包</th><th>NACK</th><th>PLI/FIR</th></tr>
              </thead>
              <tbody>
                {Object.entries(report.rtcp).map(([label, r]) => (
                  <tr key={label}>
                    <td>{label}</td>
                    <td>{r.kind}</td>
                    <td>{r.rr?.fractionLostPct != null ? r.rr.fractionLostPct : "—"}</td>
                    <td>{r.rr?.cumLost != null ? r.rr.cumLost : "—"}</td>
                    <td>{r.fb?.nack ? `${r.fb.nack.requested ?? 0} 个请求` : "—"}</td>
                    <td>{r.fb?.pli || r.fb?.fir ? (r.fb.pli?.count ?? 0) + (r.fb.fir?.count ?? 0) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* 元信息 */}
        <p className="small muted">
          报告生成于 {report.metadata?.generatedAt} · 方向 {report.metadata?.direction} · 范围 {report.metadata?.mediaType} ·{" "}
          {report.metadata?.numCaptures} 份抓包
        </p>
      </div>
    </div>
  );
}

function DelayBlock({ report }: { report: Report }) {
  const d = report.delay;
  if (!d) return <p className="small muted">未启用延迟分析或无数据。</p>;
  return (
    <div>
      {d.fsInternal?.available ? (
        <div className="report-item small">
          <span className="title">FS 内部处理延迟</span>：均值 {fmt(d.fsInternal.mean)} ms · P95{" "}
          {fmt(d.fsInternal.p95)} ms · P99 {fmt(d.fsInternal.p99)} ms · 最大 {fmt(d.fsInternal.max)} ms ·{" "}
          {d.fsInternal.count} 对样本（&gt;50ms {d.fsInternal.outliers50ms} 次 / &gt;100ms {d.fsInternal.outliers100ms} 次）
        </div>
      ) : (
        <p className="small muted">FS 内部延迟：未测量（需要 FS 抓包）。</p>
      )}
      {(d.crossCapture || []).map((c, i) => (
        <div key={i} className="report-item small">
          <span className="title">跨抓包传输延迟</span>：{c.label} — 均值 {fmt(c.mean)} ms · P95 {fmt(c.p95)} ms
          {c.clockOffsetMs != null && ` · 估算时钟偏移 ${fmt(c.clockOffsetMs)} ms（已修正）`}
        </div>
      ))}
      {d.endToEnd && d.endToEnd.totalMean != null && (
        <div className="report-item small">
          <span className="title">端到端延迟估算</span>：均值 {fmt(d.endToEnd.totalMean)} ms · P95{" "}
          {fmt(d.endToEnd.totalP95)} ms · P99 {fmt(d.endToEnd.totalP99)} ms
          {d.endToEnd.breakdown ? <span className="muted">（{d.endToEnd.breakdown}）</span> : null}
        </div>
      )}
    </div>
  );
}

function QualityBlock({
  entries,
  kind,
}: {
  entries?: Record<string, import("../analyzer/reporter").QualityEntryInput> | null;
  kind: string;
}) {
  const list = Object.entries(entries || {});
  if (!list.length) return null;
  return (
    <div>
      <p className="small" style={{ fontWeight: 600, margin: "6px 0 4px" }}>{kind}</p>
      {list.map(([label, q]) => (
        <div key={label} className={`report-item small ${q.verdict && !["clean", "ok"].includes(q.verdict) ? "warning" : "ok"}`}>
          <span className="title">{label}</span>{" "}
          {q.verdict ? (["clean", "ok"].includes(q.verdict) ? "✅ 正常" : `⚠️ ${q.verdict}`) : ""}
          {!q.decodable && <span className="muted">（{q.codec || "该编码"} 不可解码，仅 RTP 层证据）</span>}
          {(q.issues || []).map((iss, i) => (
            <div key={i} className="small">
              [{iss.severity}] {iss.message}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function fmt(x: number | null | undefined): string {
  if (x == null || Number.isNaN(x)) return "—";
  return Math.abs(x) >= 100 ? x.toFixed(0) : x.toFixed(1);
}
