// RTCP SR/RR 与反馈包（NACK/PLI/FIR）解析器（rtcp_parser.py 的 TS 移植）
import type { RtcpEvent, RtcpReportBlock } from './types';

const PT_SR = 200;
const PT_RR = 201;
const PT_RTPFB = 205;
const PT_PSFB = 206;
const FMT_NACK = 1;
const FMT_PLI = 1;
const FMT_FIR = 2;
const MAX_SUBPACKETS = 16;

/** 解析一个 UDP 数据报里的 RTCP 复合包，返回其中的事件列表 */
export function parseRtcp(payload: Uint8Array): Omit<RtcpEvent, 'time' | 'src' | 'dst'>[] {
  const events: Omit<RtcpEvent, 'time' | 'src' | 'dst'>[] = [];
  let offset = 0;
  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  for (let i = 0; i < MAX_SUBPACKETS; i++) {
    if (payload.length - offset < 4) break;
    const b0 = payload[offset];
    const pt = payload[offset + 1];
    if (b0 >> 6 !== 2) return events;
    const words = dv.getUint16(offset + 2);
    const total = (words + 1) * 4;
    if (total < 4 || offset + total > payload.length) break;
    const chunk = payload.subarray(offset, offset + total);
    try {
      if (pt === PT_SR && chunk.length >= 28) events.push(parseSr(chunk));
      else if (pt === PT_RR && chunk.length >= 8) events.push(parseRr(chunk));
      else if (pt === PT_RTPFB && (b0 & 0x1f) === FMT_NACK && chunk.length >= 12)
        events.push(parseNack(chunk));
      else if (
        pt === PT_PSFB &&
        (b0 & 0x1f) === FMT_PLI &&
        chunk.length >= 12
      )
        events.push(parsePsfb(chunk, FMT_PLI));
      else if (pt === PT_PSFB && (b0 & 0x1f) === FMT_FIR && chunk.length >= 12)
        events.push(parsePsfb(chunk, FMT_FIR));
    } catch {
      // 结构不合法：丢弃该子包
    }
    offset += total;
  }
  return events;
}

function parseSr(chunk: Uint8Array): Omit<RtcpEvent, 'time' | 'src' | 'dst'> {
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  return {
    kind: 'SR',
    ssrc: dv.getUint32(4),
    ntpSec: dv.getUint32(8),
    ntpFrac: dv.getUint32(12),
    rtpTs: dv.getUint32(16),
    pktCount: dv.getUint32(20),
    octetCount: dv.getUint32(24),
    reports: parseReportBlocks(chunk, 28, chunk[0] & 0x1f),
  };
}

function parseRr(chunk: Uint8Array): Omit<RtcpEvent, 'time' | 'src' | 'dst'> {
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  return {
    kind: 'RR',
    ssrc: dv.getUint32(4),
    reports: parseReportBlocks(chunk, 8, chunk[0] & 0x1f),
  };
}

function parseNack(chunk: Uint8Array): Omit<RtcpEvent, 'time' | 'src' | 'dst'> {
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  const mediaSsrc = dv.getUint32(8);
  let requested = 0;
  let records = 0;
  for (let i = 12; i < chunk.length - 3; i += 4) {
    records += 1;
    const blp = dv.getUint16(i + 2);
    requested += 1 + popcount(blp);
  }
  return {
    kind: 'NACK',
    ssrc: dv.getUint32(4),
    mediaSsrc,
    packets: records,
    requested,
  };
}

function parsePsfb(chunk: Uint8Array, fmt: number): Omit<RtcpEvent, 'time' | 'src' | 'dst'> {
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  const sender = dv.getUint32(4);
  const media = dv.getUint32(8);
  return { kind: fmt === FMT_PLI ? 'PLI' : 'FIR', ssrc: sender, mediaSsrc: media };
}

function parseReportBlocks(chunk: Uint8Array, start: number, rc: number): RtcpReportBlock[] {
  const reports: RtcpReportBlock[] = [];
  const n = Math.min(rc, Math.floor((chunk.length - start) / 24));
  for (let i = 0; i < n; i++) {
    const b = chunk.subarray(start + i * 24, start + (i + 1) * 24);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    reports.push({
      ssrc: dv.getUint32(0),
      fractionLostPct: Math.round((b[4] / 255) * 1000) / 10,
      cumLost: (b[5] << 16) | (b[6] << 8) | b[7],
      extHighSeq: dv.getUint32(8),
      jitter: dv.getUint32(12),
      lsr: dv.getUint32(16),
      dlsr: dv.getUint32(20),
    });
  }
  return reports;
}

function popcount(x: number): number {
  let c = 0;
  while (x) {
    x &= x - 1;
    c++;
  }
  return c;
}

export interface RtcpSrSummary {
  count: number;
  lastTime: number;
  pktCount?: number;
  octetCount?: number;
  rtpTs?: number;
  ntpSec?: number;
  ntpFrac?: number;
}

export interface RtcpRrSummary {
  count: number;
  lastTime: number;
  fractionLostPct: number;
  cumLost: number;
  jitter: number;
  reporters: number[];
}

export interface RtcpFbEntry {
  nack?: { packets: number; requested: number; lastTime: number; reporters: number[] };
  pli?: { count: number; lastTime: number; reporters: number[] };
  fir?: { count: number; lastTime: number; reporters: number[] };
}

export interface RtcpSummary {
  sr: Record<number, RtcpSrSummary>;
  rr: Record<number, RtcpRrSummary>;
  fb?: Record<number, RtcpFbEntry>;
}

/** 把一份抓包的 RTCP 事件汇总成按 SSRC 索引的最新状态 */
export function summarizeRtcp(rtpData: {
  rtcpEvents?: RtcpEvent[];
}): RtcpSummary {
  const sr: Record<number, RtcpSrSummary> = {};
  const rr: Record<number, RtcpRrSummary> = {};
  const fb: Record<number, RtcpFbEntry> = {};
  for (const ev of rtpData.rtcpEvents || []) {
    const t = ev.time || 0;
    if (ev.kind === 'SR') {
      const cur = sr[ev.ssrc];
      if (!cur || t >= cur.lastTime) {
        sr[ev.ssrc] = {
          count: cur ? cur.count + 1 : 1,
          lastTime: t,
          pktCount: ev.pktCount,
          octetCount: ev.octetCount,
          rtpTs: ev.rtpTs,
          ntpSec: ev.ntpSec,
          ntpFrac: ev.ntpFrac,
        };
      }
    } else if (ev.kind === 'RR') {
      for (const rep of ev.reports || []) {
        const ssrc = rep.ssrc;
        const cur = rr[ssrc];
        if (!cur) {
          rr[ssrc] = {
            count: 1,
            lastTime: t,
            fractionLostPct: rep.fractionLostPct,
            cumLost: rep.cumLost,
            jitter: rep.jitter,
            reporters: [ev.ssrc],
          };
        } else {
          cur.count += 1;
          if (!cur.reporters.includes(ev.ssrc)) cur.reporters.push(ev.ssrc);
          if (t >= cur.lastTime) {
            cur.lastTime = t;
            cur.fractionLostPct = rep.fractionLostPct;
            cur.cumLost = rep.cumLost;
            cur.jitter = rep.jitter;
          }
        }
      }
    } else if (ev.kind === 'NACK' || ev.kind === 'PLI' || ev.kind === 'FIR') {
      const m = (fb[ev.mediaSsrc!] ??= {});
      const key = ev.kind.toLowerCase() as 'nack' | 'pli' | 'fir';
      const cur = m[key];
      if (!cur) {
        if (key === 'nack') {
          m.nack = {
            lastTime: t,
            reporters: [ev.ssrc],
            packets: ev.packets || 0,
            requested: ev.requested || 0,
          };
        } else {
          m[key] = { count: 1, lastTime: t, reporters: [ev.ssrc] };
        }
      } else {
        cur.reporters.push(ev.ssrc);
        if (t >= cur.lastTime) cur.lastTime = t;
        if (key === 'nack' && m.nack) {
          m.nack.packets += ev.packets || 0;
          m.nack.requested += ev.requested || 0;
        } else if (key !== 'nack' && m[key]) {
          (m[key] as { count: number }).count += 1;
        }
      }
    }
  }
  const out: RtcpSummary = { sr, rr };
  if (Object.keys(fb).length) out.fb = fb;
  return out;
}
