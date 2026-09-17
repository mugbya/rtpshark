// 声音/画面问题分类卡片（problemTaxonomy 输出的渲染）
import type { ProblemClassification } from "../analyzer/reporter";

const SEV_BADGE: Record<string, string> = {
  critical: "red",
  warning: "yellow",
  info: "blue",
};

const SEV_TEXT: Record<string, string> = {
  critical: "严重",
  warning: "警告",
  info: "提示",
};

export function ProblemCards({
  audio,
  video,
}: {
  audio?: ProblemClassification | null;
  video?: ProblemClassification | null;
}) {
  return (
    <div>
      {audio && <ClassificationBlock cls={audio} kind="声音问题" />}
      {video && <ClassificationBlock cls={video} kind="画面问题" />}
    </div>
  );
}

function ClassificationBlock({
  cls,
  kind,
}: {
  cls: ProblemClassification;
  kind: string;
}) {
  if (!cls.available) {
    return <p className="small muted">{cls.summary || `${kind}：当前分析不可用。`}</p>;
  }
  return (
    <div>
      <p className="small muted">{cls.summary}</p>
      {cls.problems.length === 0 && (
        <div className="report-item ok small">✅ 未检出{kind}（抓包层面）</div>
      )}
      {cls.problems.map((p) => (
        <div key={p.id} className={`report-item ${p.severity === "critical" ? "critical" : p.severity === "warning" ? "warning" : "info"}`}>
          <div>
            <span className={`badge ${SEV_BADGE[p.severity] || "gray"}`}>
              {p.priority} · {SEV_TEXT[p.severity] || p.severity}
            </span>
            <span className="badge gray">{p.category}</span>
            <span className="title"> {p.name}</span>
          </div>
          {p.feel.length > 0 && (
            <div className="small mt-2">
              用户常说：{p.feel.map((f) => `「${f}」`).join("、")}
            </div>
          )}
          <div className="small mt-2">{p.description}</div>
          {p.evidence.length > 0 && (
            <div className="small mt-2">
              <strong>证据</strong>
              {p.evidence.map((e, i) => (
                <div key={i}>· {e}</div>
              ))}
            </div>
          )}
          <div className="small mt-2">
            <strong>排查方向</strong>
            {p.causes.map((c, i) => (
              <div key={i}>· {c}</div>
            ))}
          </div>
          {p.verify.length > 0 && (
            <div className="small mt-2 muted">
              <strong>验证方法</strong>
              {p.verify.map((v, i) => (
                <div key={i}>· {v}</div>
              ))}
            </div>
          )}
        </div>
      ))}

      {cls.notes.map((n, i) => (
        <div key={i} className="banner info small">{n}</div>
      ))}

      {cls.unobservable.length > 0 && (
        <details className="block">
          <summary className="small">
            抓包无法确认的{kind}（{cls.unobservable.length} 类，附人工验证方法）
          </summary>
          <table className="plain mt-2">
            <thead>
              <tr><th>问题</th><th>类别</th><th>为什么抓包看不到</th><th>人工验证方法</th></tr>
            </thead>
            <tbody>
              {cls.unobservable.map((u) => (
                <tr key={u.name}>
                  <td>{u.name}<div className="small muted">{u.feel.join("、")}</div></td>
                  <td>{u.category}</td>
                  <td className="small">{u.why}</td>
                  <td className="small">{u.verify}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}
