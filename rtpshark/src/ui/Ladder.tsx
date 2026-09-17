// SIP 信令阶梯图 —— 渲染 callDetector.buildSipFlows 产出的去重信令流（SipFlowItem），
// 并对齐 Python Web 版的三类标注：
//   1) RTP 媒体开始/结束标线（成对插在首条 BYE 行之前，无 BYE 按媒体结束时间兜底）
//   2) 两腿协商编码行（主叫/被叫各一行，锚在该腿应答行之后；无 per-leg 数据时
//      回退为单行 negotiatedCodecs 汇总）
//   3) FS 媒体处理（转码）判定行（固定在 RTP 开始标线之前）
import type { CallInfo } from "../analyzer/types";
import type { SipFlowItem, SipFlowKind } from "../analyzer/callDetector";

const KIND_COLORS: Record<SipFlowKind, string> = {
  request: "#2563eb", // 请求（INVITE/ACK/BYE…）蓝色
  provisional: "#94a3b8", // 1xx 灰色
  success: "#16a34a", // 2xx 绿色
  error: "#dc2626", // 3xx-6xx 红色
};

type Chip = { icon: string; text: string };

function codecChips(leg: { audio?: string[]; video?: string[] }): Chip[] {
  const chips: Chip[] = [];
  if (leg.audio?.length) chips.push({ icon: "🎵", text: `音频 ${leg.audio.join(" / ")}` });
  if (leg.video?.length) chips.push({ icon: "🎬", text: `视频 ${leg.video.join(" / ")}` });
  return chips;
}

type Row =
  | { t: "msg"; ev: SipFlowItem; i: number }
  | { t: "marker"; kind: "start" | "end"; text: string }
  | { t: "chips"; label: string; chips: Chip[] }
  | { t: "fs"; verdict: NonNullable<CallInfo["fsMedia"]> };

export function Ladder({ call }: { call: CallInfo }) {
  const events = call.signaling || [];
  if (!events || events.length === 0) {
    return <p className="muted small">该通话没有抓到对话相关 SIP 信令。</p>;
  }

  // 列 = 参与方 IP，按首条消息发送方排前
  const cols: string[] = [];
  for (const ev of events) {
    if (!cols.includes(ev.src)) cols.push(ev.src);
    if (!cols.includes(ev.dst)) cols.push(ev.dst);
  }
  const n = cols.length;
  const colOf = (ip: string) => cols.indexOf(ip);
  const centerPct = (i: number) => `${((i + 0.5) / n) * 100}%`;

  // 消息行；rowBefore/rowAfter 记录每条消息的行下标，供标线/协商行锚定
  const rows: Row[] = [];
  const rowBefore: number[] = [];
  const rowAfter: number[] = [];
  events.forEach((ev, i) => {
    rowBefore[i] = rows.length;
    rows.push({ t: "msg", ev, i });
    rowAfter[i] = rows.length;
  });

  // RTP 媒体开始/结束标线（talk_* 是应答后的 RTP 首末包时间，缺头缺尾通话回退为整段媒体）
  const sStr = call.talkStartStr || call.startStr;
  const eStr = call.talkEndStr || call.endStr;
  const dur = call.talkDurationS ?? call.durationS;
  // 结束位置：首条 BYE 行之前；无 BYE 再按媒体结束时间插
  let ek = events.findIndex((m) => m.method === "BYE");
  if (ek === -1 && eStr) ek = events.findIndex((m) => m.timeStr >= eStr);
  const ei = ek === -1 ? rows.length : rowBefore[ek];
  const si = ei;

  // 待插入行 {anchor, prio, row}：统一按锚点从大到小 splice（大锚点先插不会
  // 影响更小的锚点位置）。同锚点时 prio 大的先插、最终排在后面——FS 判定行
  // 因此排在同位置的协商行之后
  const inserts: { anchor: number; prio: number; row: Row }[] = [];
  if (eStr)
    inserts.push({
      anchor: ei,
      prio: 0,
      row: { t: "marker", kind: "end", text: `RTP 媒体结束 ${eStr}（持续 ${dur}s）` },
    });
  if (sStr)
    inserts.push({
      anchor: si,
      prio: 0,
      row: { t: "marker", kind: "start", text: `RTP 媒体开始 ${sStr}` },
    });
  // 通话实际用到的编码 chips（汇总字段 codecs）：跟在开始标线之后
  {
    const chips = codecChips(call.codecs || {});
    if (chips.length)
      inserts.push({
        anchor: si + 1,
        prio: 0,
        row: { t: "chips", label: "实际编码", chips },
      });
  }

  // 两腿协商编码：每条腿记住最后一条带编码名的 SDP 行下标（= 该腿应答行），
  // 协商行锚在这行之后——即协商完成的时刻，不早于该腿的应答出现在图上
  const legAnchors: Record<string, number> = {};
  const sdpRows: number[] = [];
  events.forEach((m, i) => {
    if (m.sdpCodecs && (m.sdpCodecs.audio?.length || m.sdpCodecs.video?.length)) {
      sdpRows.push(rowAfter[i]);
      if (m.callId) legAnchors[m.callId] = rowAfter[i];
    }
  });
  // 兜底锚点：第二条 SDP 行之后（即首个 offer/answer 对完成处），且不晚于开始标线
  let ni = sdpRows.length >= 2 ? sdpRows[1] : sdpRows.length === 1 ? sdpRows[0] : si;
  ni = Math.min(ni, si);

  const npl = call.negotiatedPerLeg || {};
  let legInserted = false;
  for (const [key, name] of [
    ["caller", "主叫"],
    ["callee", "被叫"],
  ] as const) {
    const leg = npl[key];
    if (!leg) continue;
    const chips = codecChips(leg);
    if (!chips.length) continue;
    legInserted = true;
    const label =
      leg.answered === false ? `${name}候选编码（未收到应答）` : `${name}侧协商`;
    const anchor =
      leg.callId && legAnchors[leg.callId] != null
        ? Math.min(legAnchors[leg.callId], si)
        : ni;
    inserts.push({ anchor, prio: 0, row: { t: "chips", label, chips } });
  }
  if (!legInserted) {
    // 兜底：单行协商编码汇总（无 per-leg 数据时）
    const chips = codecChips(call.negotiatedCodecs || {});
    if (chips.length) {
      const label =
        call.sdpAnswered === false ? "主叫候选编码（未收到应答）" : "协商编码";
      inserts.push({ anchor: ni, prio: 0, row: { t: "chips", label, chips } });
    }
  }
  // FS 是否参与编解码（对比两腿协商编码 + 媒体路径判定）：固定在 RTP 开始标线之前
  const fm = call.fsMedia;
  if (fm && fm.verdict) {
    inserts.push({ anchor: si, prio: 1, row: { t: "fs", verdict: fm } });
  }

  inserts.sort((a, b) => b.anchor - a.anchor || b.prio - a.prio);
  for (const it of inserts) rows.splice(it.anchor, 0, it.row);

  const FS_META: Record<string, { cls: string; label: string }> = {
    transcode: { cls: "red", label: "FS 参与转码" },
    same: { cls: "green", label: "FS 未转码" },
    bypass: { cls: "blue", label: "媒体不经 FS" },
    unknown: { cls: "gray", label: "无法判定" },
  };

  return (
    <div className="ladder">
      {/* 列头：参与者 IP（与轨道区对齐，时间列占 72px） */}
      <div className="ld-head" style={{ gridTemplateColumns: `72px repeat(${n}, 1fr)` }}>
        <span />
        {cols.map((ip) => (
          <span key={ip} className="ld-col" title={ip}>
            {ip}
          </span>
        ))}
      </div>
      <div className="ld-body">
        {/* 轨道区纵向生命线：只覆盖时间列右侧的轨道区 */}
        <div className="ld-lines">
          {cols.map((ip, i) => (
            <i key={ip} className="ld-vline" style={{ left: centerPct(i) }} />
          ))}
        </div>
        {rows.map((row, i) => {
          if (row.t === "msg") {
            const ev = row.ev;
            const a = colOf(ev.src);
            const b = colOf(ev.dst);
            const color = KIND_COLORS[ev.kind] ?? KIND_COLORS.request;
            const lo = Math.min(a, b);
            const hi = Math.max(a, b);
            const left = centerPct(lo);
            const width = `${((hi - lo) / n) * 100}%`;
            const toRight = b >= a;
            return (
              <div key={i} className="ld-row">
                <span className="ld-t">{ev.timeStr}</span>
                <div className="ld-track">
                  {a === b ? (
                    <span
                      className="ld-label ld-self"
                      style={{ left, color }}
                      title={ev.label}
                    >
                      {ev.label}
                    </span>
                  ) : (
                    <span className="ld-seg" style={{ left, width }}>
                      <span className="ld-label" style={{ color }} title={ev.label}>
                        {ev.label}
                      </span>
                      <i className="ld-line" style={{ background: color }} />
                      <i
                        className="ld-arrow"
                        style={{
                          [toRight ? "right" : "left"]: "-5px",
                          borderLeftColor: toRight ? color : "transparent",
                          borderRightColor: toRight ? "transparent" : color,
                        }}
                      />
                    </span>
                  )}
                </div>
              </div>
            );
          }
          if (row.t === "marker") {
            return (
              <div key={i} className={`ld-marker ${row.kind === "start" ? "ld-start" : "ld-end"}`}>
                <span className="ld-micon">{row.kind === "start" ? "▶" : "■"}</span>
                {row.text}
              </div>
            );
          }
          if (row.t === "chips") {
            return (
              <div key={i} className="ld-chips">
                <span className="ld-clabel">{row.label}</span>
                {row.chips.map((c, j) => (
                  <span key={j} className="badge gray ld-chip">
                    {c.icon} {c.text}
                  </span>
                ))}
              </div>
            );
          }
          // FS 转码判定行
          const m = FS_META[row.verdict.verdict] ?? { cls: "gray", label: "FS 媒体处理" };
          return (
            <div key={i} className="ld-chips">
              <span className={`badge ${m.cls}`}>⚙ {m.label}</span>
              <span className={row.verdict.verdict === "unknown" ? "ld-fmtext muted" : "ld-fmtext"}>
                {row.verdict.text}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
