// SIP 信令阶梯图 —— 渲染 callDetector.buildSipFlows 产出的去重信令流（SipFlowItem），
// 并对齐 Python Web 版的标注体系，编码部分按「谁支持什么 → 最终定了什么」展示：
//   1) 主叫支持的编码（主叫腿 SDP offer 列表）
//   2) FS 支持的编码（FS 发出的 SDP：主叫腿应答 + 被叫腿 offer）
//   3) 被叫支持的编码（被叫腿 SDP 应答列表）
//   4) 最终协商编码（两腿应答合并：一致取交集顺序，两腿不同则分腿列出）
//   5) RTP 媒体开始/结束标线（成对插在首条 BYE 行之前，无 BYE 按媒体结束时间兜底）
//   6) FS 媒体处理（转码）判定行
// 腿→角色映射来自 negotiatedPerLeg（caller 腿 offerer=主叫/answerer=FS，
// callee 腿 offerer=FS/answerer=被叫），无需依赖 serverIp。
import type { CallInfo } from "../analyzer/types";
import type { NegotiatedLeg, SipFlowItem, SipFlowKind } from "../analyzer/callDetector";

const KIND_COLORS: Record<SipFlowKind, string> = {
  request: "#2563eb", // 请求（INVITE/ACK/BYE…）蓝色
  provisional: "#94a3b8", // 1xx 灰色
  success: "#16a34a", // 2xx 绿色
  error: "#dc2626", // 3xx-6xx 红色
};

type Chip = { icon: string; text: string };
type Party = "caller" | "fsCaller" | "fsCallee" | "callee";
const PARTY_NAMES: Record<Party, string> = {
  caller: "主叫端支持",
  fsCaller: "FS 与主叫协商",
  fsCallee: "FS 与被叫协商",
  callee: "被叫端支持",
};

function codecChips(leg: { audio?: string[]; video?: string[] }): Chip[] {
  const chips: Chip[] = [];
  if (leg.audio?.length) chips.push({ icon: "🎵", text: `音频 ${leg.audio.join(" / ")}` });
  if (leg.video?.length) chips.push({ icon: "🎬", text: `视频 ${leg.video.join(" / ")}` });
  return chips;
}

/** 有序去重合并 SDP 编码列表 */
function mergeCodecs(
  acc: { audio: string[]; video: string[] },
  add: { audio?: string[]; video?: string[] },
): void {
  for (const k of ["audio", "video"] as const) {
    for (const c of add[k] ?? []) {
      if (!acc[k].includes(c)) acc[k].push(c);
    }
  }
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

  // 消息行；rowBefore/rowAfter 记录每条消息的行下标，供标线/编码行锚定
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
  // 因此排在同位置的编码行之后
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

  // ---- 编码协商展示：谁支持什么 / 最终定了什么 ----
  const npl = call.negotiatedPerLeg || {};
  const callerLegId = npl.caller?.callId ?? null;
  const calleeLegId = npl.callee?.callId ?? null;
  // 每条腿的 offer 发送方 = 该腿首条带 SDP 消息的发送方
  const legOfferer: Record<string, string> = {};
  for (const m of events) {
    if (m.sdpCodecs && m.callId && !(m.callId in legOfferer)) {
      legOfferer[m.callId] = m.src;
    }
  }

  // 各方在 SDP 里宣告的编码（有序去重）+ 首次宣告的消息下标（供锚定）。
  // FS 按腿拆开：对主叫是应答、对被叫是新的 offer，两条腿宣告的编码可能不同，
  // 合并成一行会掩盖差异。
  const supported: Record<Party, { codecs: { audio: string[]; video: string[] }; firstIdx: number }> = {
    caller: { codecs: { audio: [], video: [] }, firstIdx: -1 },
    fsCaller: { codecs: { audio: [], video: [] }, firstIdx: -1 },
    fsCallee: { codecs: { audio: [], video: [] }, firstIdx: -1 },
    callee: { codecs: { audio: [], video: [] }, firstIdx: -1 },
  };
  events.forEach((m, i) => {
    if (!m.sdpCodecs || !(m.sdpCodecs.audio?.length || m.sdpCodecs.video?.length)) return;
    let party: Party | null = null;
    if (m.callId && m.callId === callerLegId) {
      // 主叫腿：offer 方 = 主叫，answer 方 = FS
      party = m.src === legOfferer[m.callId] ? "caller" : "fsCaller";
    } else if (m.callId && m.callId === calleeLegId) {
      // 被叫腿：offer 方 = FS，answer 方 = 被叫
      party = m.src === legOfferer[m.callId] ? "fsCallee" : "callee";
    }
    if (!party) return;
    mergeCodecs(supported[party].codecs, m.sdpCodecs);
    if (supported[party].firstIdx === -1) supported[party].firstIdx = i;
  });
  // 各方支持编码行：锚在该方向首次宣告 SDP 的消息行之后
  for (const party of ["caller", "fsCaller", "fsCallee", "callee"] as const) {
    const s = supported[party];
    if (!(s.codecs.audio.length || s.codecs.video.length)) continue;
    const chips = codecChips(s.codecs);
    inserts.push({
      anchor: Math.min(rowAfter[s.firstIdx], si),
      prio: 0,
      row: { t: "chips", label: `${PARTY_NAMES[party]}的编码`, chips },
    });
  }

  // 最终协商编码：两腿应答合并（negotiatedPerLeg）；无按腿数据时回退
  // negotiatedCodecs 汇总。answered=false 表示只抓到 offer、没有应答。
  {
    const legs: NegotiatedLeg[] = [npl.caller, npl.callee].filter(Boolean) as NegotiatedLeg[];
    if (legs.length >= 2) {
      const same =
        legs[0].audio.join("\u0000") === legs[1].audio.join("\u0000") &&
        legs[0].video.join("\u0000") === legs[1].video.join("\u0000");
      if (same) {
        const chips = codecChips(legs[0]);
        if (chips.length)
          inserts.push({ anchor: si, prio: 0, row: { t: "chips", label: "最终协商", chips } });
      } else {
        // 两腿协商结果不同（FS 转码场景）：分腿列出
        const chips: Chip[] = [];
        for (const [leg, name] of [
          [legs[0], "主叫腿"],
          [legs[1], "被叫腿"],
        ] as [NegotiatedLeg, string][]) {
          for (const c of codecChips(leg)) {
            chips.push({ icon: c.icon, text: `${name} ${c.text}` });
          }
        }
        if (chips.length)
          inserts.push({
            anchor: si,
            prio: 0,
            row: { t: "chips", label: "最终协商（两腿不同）", chips },
          });
      }
    } else if (legs.length === 1) {
      const leg = legs[0];
      const chips = codecChips(leg);
      if (chips.length)
        inserts.push({
          anchor: si,
          prio: 0,
          row: {
            t: "chips",
            label: leg.answered ? "最终协商" : "候选编码（未收到应答）",
            chips,
          },
        });
    } else {
      // 兜底：旧数据只有汇总字段
      const chips = codecChips(call.negotiatedCodecs || {});
      if (chips.length) {
        inserts.push({
          anchor: si,
          prio: 0,
          row: {
            t: "chips",
            label: call.sdpAnswered === false ? "主叫候选编码（未收到应答）" : "协商编码",
            chips,
          },
        });
      }
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
      <p className="muted small" style={{ margin: "8px 0 0" }}>
        注：各方「编码」取自本通话 SDP 中实际宣告的内容——主叫为 INVITE offer，FS
        按腿拆分（对主叫的应答 / 对被叫的新 offer，两边可能不同），被叫为 200 OK
        应答；FS 的完整编码能力由其配置决定，抓包中不可见。
      </p>
    </div>
  );
}
