import { lazy, useMemo, useRef, useState, Suspense } from "react";
import "./App.css";
import { AnalyzerClient } from "./analyzer/workerClient";
import type { UploadSessionPublic } from "./analyzer/workerClient";
import type { AnalyzeOutput, AnalyzeParams } from "./analyzer/pipeline";
import type { CallInfo } from "./analyzer/types";
import { ResultsView } from "./ui/ResultsView";

const ROLES = [
  { id: "terminal", icon: "📱", label: "主叫端抓包（终端）" },
  { id: "fs", icon: "🖥️", label: "服务端抓包（FS）" },
  { id: "seat", icon: "🎧", label: "被叫端抓包（坐席）" },
];

const fmtTime = (t: number) =>
  new Date(t * 1000).toLocaleString("zh-CN", { hour12: false });

const INTEGRITY_BADGE: Record<string, { cls: string; text: string }> = {
  complete: { cls: "green", text: "✅ 完整" },
  missing_start: { cls: "yellow", text: "⚠️ 缺开头" },
  missing_end: { cls: "yellow", text: "⚠️ 缺结尾" },
  missing_both: { cls: "red", text: "❌ 首尾都不完整" },
};

function App() {
  const clientRef = useRef<AnalyzerClient | null>(null);
  const getClient = () => {
    if (!clientRef.current) clientRef.current = new AnalyzerClient();
    return clientRef.current;
  };

  const [picked, setPicked] = useState<Record<string, File | null>>({});
  const [session, setSession] = useState<UploadSessionPublic | null>(null);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [integrityConfirmed, setIntegrityConfirmed] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [output, setOutput] = useState<AnalyzeOutput | null>(null);

  // 分析参数
  const [callId, setCallId] = useState<string | null>(null);
  const [mediaType, setMediaType] = useState<"audio" | "video" | "all">("audio");
  const [checkDelay, setCheckDelay] = useState(true);
  const [direction, setDirection] = useState("auto");

  const hasAnyFile = Object.values(picked).some(Boolean);

  getClient().onProgress = (p) => setStatus(p.stage);

  async function handleUpload() {
    setError("");
    setStatus("正在读取文件…");
    const files = [];
    for (const [role, file] of Object.entries(picked)) {
      if (!file) continue;
      files.push({
        role,
        filename: file.name,
        bytes: await file.arrayBuffer(),
      });
    }
    try {
      const res = await getClient().upload(files);
      setSession(res);
      setOutput(null);
      setIntegrityConfirmed(false);
      // 默认选中唯一通话 / 覆盖抓包最多的通话
      const calls = res.upload.calls || [];
      if (calls.length === 1) setCallId(calls[0].callId);
      else if (calls.length > 1) {
        const best = calls.reduce((a, b) =>
          Object.keys(b.integrity?.perFile ?? {}).length >= Object.keys(a.integrity?.perFile ?? {}).length ? b : a,
        );
        setCallId(best.callId);
      } else setCallId(null);
      setStatus("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("");
    }
  }

  async function handleAnalyze() {
    if (!session) return;
    setError("");
    // 文件级完整性提醒：确认后继续（本会话只确认一次）
    if (session.upload.integrityWarning && !integrityConfirmed) {
      const ok = window.confirm(
        "以下抓包文件存在完整性问题（截短/文件尾损坏），相关统计与媒体重建可能受影响：\n\n" +
          session.upload.integrityWarning.files
            .map((f) => `【${f.role}】${f.filename}\n  ${f.notes.join("\n  ")}`)
            .join("\n\n") +
          "\n\n是否继续分析？（按现有数据照常分析）",
      );
      if (!ok) return;
      setIntegrityConfirmed(true);
    }
    setAnalyzing(true);
    setStatus("正在分析…");
    const params: AnalyzeParams = {
      callId,
      mediaType,
      direction,
      checkDelay,
    };
    try {
      const out = await getClient().analyze([], session.upload, params);
      setOutput(out);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setAnalyzing(false);
      setStatus("");
    }
  }

  const singleCaptureNoFs =
    (session?.upload.files.length || 0) < 2 &&
    !session?.upload.files.some((f) => f.role.toLowerCase() === "fs");

  const calls: CallInfo[] = session?.upload.calls || [];

  const selectedCall = useMemo(
    () => calls.find((c) => c.callId === callId) || null,
    [calls, callId],
  );

  return (
    <main className="container">
      <div className="hero">
        <h1>RTPShark · RTP 音视频流分析</h1>
        <p>加载抓包文件，自动分析延迟、抖动、丢包与音画异常</p>
      </div>

      {/* Step 1: 文件选择 */}
      <div className="card">
        <div className="card-header step-1">① 选择抓包文件</div>
        <div className="card-body">
          <p className="muted small mb-2">
            支持 pcap / pcapng 格式。可加载 1~3 个文件，系统自动识别端点角色；缺失某个抓包点时，对应分析项自动置灰。
          </p>
          <div className="upload-grid">
            {ROLES.map((r) => (
              <label
                key={r.id}
                className={`upload-box ${picked[r.id] ? "has-file" : ""}`}
              >
                <span className="icon">{r.icon}</span>
                <span className="label">{r.label}</span>
                <span className="hint">（可选项）</span>
                <div className="file-name">{picked[r.id]?.name || ""}</div>
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={(e) =>
                    setPicked((p) => ({
                      ...p,
                      [r.id]: e.target.files?.[0] || null,
                    }))
                  }
                />
              </label>
            ))}
          </div>
          <div className="center mt-3">
            <button
              className="btn btn-primary btn-lg"
              disabled={!hasAnyFile || analyzing}
              onClick={handleUpload}
            >
              上传并识别
            </button>
          </div>
        </div>
      </div>

      {error && <div className="banner error">❌ {error}</div>}

      {/* Step 2: 识别结果 */}
      {session && (
        <div className="card">
          <div className="card-header step-2">② 流识别结果</div>
          <div className="card-body">
            <div className="mb-2">
              <span className="badge blue">服务器 IP: {session.upload.serverIp || "未检测到"}</span>
              <span className="badge gray">音频流: {session.upload.audioStreams}</span>
              <span className="badge gray">视频流: {session.upload.videoStreams}</span>
            </div>

            {session.upload.files.map((f) => (
              <div key={f.role} className="file-summary">
                <strong>【{f.role}】{f.filename}</strong>
                <span className="muted">
                  {" "}
                  — {f.totalPackets} 个 RTP 包 · {f.streamCount} 条流 · IP: {f.ips.join(", ") || "无"}
                </span>
                {f.integrity?.status === "warn" && (
                  <div className="small" style={{ color: "var(--warn)" }}>
                    {f.integrity.notes.map((n, i) => (
                      <div key={i}>⚠️ {n}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {session.upload.captureWarning && (
              <div className="banner warn">
                ⚠️ 可能传错了文件：各抓包之间未找到共享的同一通通话。
                <details className="mt-2">
                  <summary className="small">各角色检测到的通话</summary>
                  <pre className="small" style={{ whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(session.upload.captureWarning, null, 2)}
                  </pre>
                </details>
              </div>
            )}

            <h4 style={{ margin: "10px 0 8px" }}>检测到的通话（{calls.length}）</h4>
            {calls.length === 0 && (
              <p className="muted small">未检出通话（可能缺少 SIP 信令或媒体流太少）。</p>
            )}
            {calls.map((c, idx) => {
              const badge = INTEGRITY_BADGE[
                overallIntegrity(c)
              ] || { cls: "gray", text: "—" };
              return (
                <div key={c.callId || idx} className="call-card">
                  <div>
                    <span className="badge gray">通话 {idx + 1}</span>
                    <span className="badge blue">Call-ID: {c.callId || "（无信令）"}</span>
                    <span className="badge">流数: {c.ssrcs?.length ?? c.streams ?? "—"}</span>
                    <span className="badge">开始: {fmtTime(c.startTime)}</span>
                    <span className="badge">结束: {fmtTime(c.endTime)}</span>
                    <span className={`badge ${badge.cls}`}>{badge.text}</span>
                  </div>
                  <details className="mt-2">
                    <summary className="small muted">判断依据与信令流程</summary>
                    {c.integrity && Object.entries(c.integrity.perFile ?? {}).map(([role, v]) => (
                      <div key={role} className="small mt-2">
                        <strong>{role}</strong>（{v.status}）：
                        {v.reasons?.length ? v.reasons.join("；") : "—"}
                      </div>
                    ))}
                    {c.signaling?.length ? (
                      <details className="mt-2">
                        <summary className="small">SIP 信令阶梯图（{c.signaling.length} 条）</summary>
                        <CallLadder call={c} />
                      </details>
                    ) : (
                      <p className="small muted mt-2">无对话信令</p>
                    )}
                  </details>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Step 3: 分析参数 */}
      {session && (
        <div className="card">
          <div className="card-header step-3">③ 选择分析参数</div>
          <div className="card-body">
            {calls.length > 1 && (
              <div className="mb-2">
                <strong>选择通话</strong>
                <div className="row mt-2">
                  {calls.map((c, idx) => (
                    <button
                      key={c.callId || idx}
                      className={`btn ${callId === c.callId ? "btn-primary" : ""}`}
                      style={{ flex: "0 1 auto" }}
                      onClick={() => setCallId(c.callId)}
                    >
                      通话 {idx + 1}（{c.ssrcs?.length ?? "?"} 条流）
                    </button>
                  ))}
                  <button
                    className={`btn ${callId === null ? "btn-primary" : ""}`}
                    style={{ flex: "0 1 auto" }}
                    onClick={() => setCallId(null)}
                  >
                    全部混合（可能失真）
                  </button>
                </div>
                <p className="small" style={{ color: "var(--danger)" }}>
                  多通通话混在一起分析会使延迟/抖动结果失真，建议选择具体通话。
                </p>
              </div>
            )}

            <div className="row">
              <div>
                <strong>分析范围（媒体类型）</strong>
                <div className="radio-cards mt-2">
                  {[
                    { v: "audio", t: "仅音频", d: "杂音 / 啸叫 / 断音吞字等声音问题" },
                    { v: "video", t: "仅视频", d: "花屏 / 马赛克 / 卡顿冻结等画面问题" },
                    { v: "all", t: "音视频都分析", d: "声音 + 画面两侧问题都查" },
                  ].map((o) => (
                    <label
                      key={o.v}
                      className={`radio-card ${mediaType === o.v ? "selected" : ""}`}
                    >
                      <input
                        type="radio"
                        name="mediaType"
                        checked={mediaType === o.v}
                        onChange={() => setMediaType(o.v as typeof mediaType)}
                      />
                      <span>
                        {o.t}
                        <div className="desc">{o.d}</div>
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <strong>分析内容</strong>
                <label className="mt-2" style={{ display: "block" }}>
                  <input
                    type="checkbox"
                    checked={checkDelay && !singleCaptureNoFs}
                    disabled={singleCaptureNoFs}
                    onChange={(e) => setCheckDelay(e.target.checked)}
                  />{" "}
                  延迟测量（FS 内部 / 跨抓包 / 端到端）
                </label>
                {singleCaptureNoFs && (
                  <p className="small muted">
                    单端抓包（且非 FS）无法测量延迟，已自动禁用；抖动/丢包与音画质量不受影响。
                  </p>
                )}
                <p className="small muted">
                  音画质量（杂音/啸叫/花屏等）已随「分析范围」自动包含。
                </p>
              </div>

              <div>
                <strong>延迟方向</strong>
                <div className="mt-2">
                  <label style={{ display: "block" }}>
                    <input
                      type="radio"
                      name="direction"
                      checked={direction === "auto"}
                      onChange={() => setDirection("auto")}
                    />{" "}
                    自动
                  </label>
                  {(session.upload.availableDirections || []).map((d) => (
                    <label key={d.id} style={{ display: "block" }}>
                      <input
                        type="radio"
                        name="direction"
                        checked={direction === d.id}
                        onChange={() => setDirection(d.id)}
                      />{" "}
                      {d.label}
                    </label>
                  ))}
                </div>
                <p className="small muted">根据上传的抓包文件自动识别可用方向。</p>
              </div>
            </div>

            <div className="center mt-3">
              <button
                className="btn btn-warn btn-lg"
                disabled={analyzing}
                onClick={handleAnalyze}
              >
                {analyzing ? "分析中…" : "开始分析"}
              </button>
            </div>
            {selectedCall && (
              <p className="center small muted mt-2">
                当前分析：通话 {calls.findIndex((c) => c.callId === callId) + 1}（Call-ID: {selectedCall.callId}）
              </p>
            )}
          </div>
        </div>
      )}

      {output && session && (
        <ResultsView
          output={output}
          upload={session.upload}
          mediaType={mediaType}
          checkDelay={checkDelay}
        />
      )}

      {status && <div className="status-line">{status}</div>}
      <p className="footer-note">
        RTPShark — 基于 rtp-stream-analyzer 的桌面版 · 延迟/抖动/丢包/音画质量/媒体重建
      </p>
    </main>
  );
}

function overallIntegrity(c: CallInfo): string {
  const entries = Object.values(c.integrity?.perFile ?? {});
  if (!entries.length) return "complete";
  if (entries.every((e) => e.status === "complete")) return "complete";
  if (entries.some((e) => e.status === "missing_both")) return "missing_both";
  if (entries.some((e) => e.status === "missing_start")) return "missing_start";
  if (entries.some((e) => e.status === "missing_end")) return "missing_end";
  return "complete";
}

// 阶梯图体积可观，懒加载
const Ladder = lazy(() =>
  import("./ui/Ladder").then((m) => ({ default: m.Ladder })),
);

function CallLadder(props: { call: import("./analyzer/types").CallInfo }) {
  return (
    <Suspense fallback={<p className="small muted">信令图加载中…</p>}>
      <Ladder {...props} />
    </Suspense>
  );
}

export default App;
