// 抓包文件完整性检测（capture_integrity.py 的 TS 移植，输入改为内存字节）
// 对应 Wireshark 的两类提示：
// 1. "Packet size limited during capture"（快照截短）：orig_len > incl_len
// 2. "…cut off in the middle of a packet"（文件尾不完整记录）
// 两类都只提示、不阻断分析。
import type { CaptureIntegrityResult } from './types';

/** 少于该字节数的“缺失”不视为截断（链路层 FCS 等统计口径噪声） */
export const TRUNC_MIN_BYTES = 8;

export interface PcapHeaderStats {
  snaplen: number | null;
  recordCount: number;
  truncatedRecords: number;
  tailIncomplete: boolean;
  minCapturedTrunc: number | null;
}

export interface PcapRecord {
  time: number; // 秒（epoch，含小数）
  data: Uint8Array; // 链路层帧（captured 部分）
  wirelen: number; // 线上原始长度
}

const PCAP_MAGICS = new Map<number, boolean>([
  [0xa1b2c3d4, false],
  [0xd4c3b2a1, false],
  [0xa1b23c4d, true], // 纳秒分辨率
  [0x4d3cb2a1, true],
]);
const SHB_MAGIC = 0x0a0d0d0a;

const u32 = (b: Uint8Array, off: number, little: boolean) =>
  little
    ? ((b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0)
    : (((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0);

/**
 * 走查抓包文件原始记录头 + 提取全部包记录。
 * 一个包都不读不出时抛错（格式无效）；文件尾损坏时带 tailIncomplete 继续。
 */
export function readPcapBytes(buf: Uint8Array): {
  records: PcapRecord[];
  stats: PcapHeaderStats | null;
} {
  if (buf.length < 4) throw new Error('文件太小，不是抓包文件');
  const magic = u32(buf, 0, false);
  if (PCAP_MAGICS.has(magic)) {
    const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
    const nanos = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    return readPcapClassic(buf, little, nanos);
  }
  if (magic === SHB_MAGIC) return readPcapng(buf);
  throw new Error('不是 pcap/pcapng 文件');
}

function readPcapClassic(buf: Uint8Array, little: boolean, nanos: boolean) {
  if (buf.length < 24) throw new Error('pcap 全局头不完整');
  const snaplen = u32(buf, 16, little);
  const stats: PcapHeaderStats = {
    snaplen: snaplen || null,
    recordCount: 0,
    truncatedRecords: 0,
    tailIncomplete: false,
    minCapturedTrunc: null,
  };
  const records: PcapRecord[] = [];
  let off = 24;
  while (off < buf.length) {
    if (buf.length - off < 16) {
      stats.tailIncomplete = true;
      break;
    }
    const tsSec = u32(buf, off, little);
    const tsFrac = u32(buf, off + 4, little);
    const inclLen = u32(buf, off + 8, little);
    const origLen = u32(buf, off + 12, little);
    if (buf.length - off - 16 < inclLen) {
      // 包体中途结束：文件尾被截断，保留可读部分
      stats.tailIncomplete = true;
      const avail = buf.length - off - 16;
      if (avail > 0) {
        records.push({
          time: tsSec + (nanos ? tsFrac / 1e9 : tsFrac / 1e6),
          data: buf.subarray(off + 16, off + 16 + avail),
          wirelen: origLen,
        });
      }
      break;
    }
    records.push({
      time: tsSec + (nanos ? tsFrac / 1e9 : tsFrac / 1e6),
      data: buf.subarray(off + 16, off + 16 + inclLen),
      wirelen: origLen,
    });
    off += 16 + inclLen;
    stats.recordCount += 1;
    if (origLen - inclLen >= TRUNC_MIN_BYTES) {
      stats.truncatedRecords += 1;
      stats.minCapturedTrunc =
        stats.minCapturedTrunc === null
          ? inclLen
          : Math.min(stats.minCapturedTrunc, inclLen);
    }
  }
  return { records, stats };
}

function readPcapng(buf: Uint8Array) {
  if (buf.length < 12) throw new Error('pcapng SHB 不完整');
  const bom = u32(buf, 4, false);
  let little: boolean;
  if (bom === 0x1a2b3c4d) little = true;
  else if (bom === 0x4d3c2b1a) little = false;
  else throw new Error('pcapng 字节序无法识别');
  const stats: PcapHeaderStats = {
    snaplen: null,
    recordCount: 0,
    truncatedRecords: 0,
    tailIncomplete: false,
    minCapturedTrunc: null,
  };
  const records: PcapRecord[] = [];
  let off = 0;
  // 时间戳：EPB 用 (iface 高精度) 简化处理 —— 取 高32位*2^32+低32位，单位由
  // IDB if_tsresolu 决定，默认 1e-6 秒（大多数抓包工具的默认行为）
  let tsResolu = 1e6;
  let first = true;
  while (off < buf.length) {
    if (buf.length - off < 8) {
      stats.tailIncomplete = true;
      break;
    }
    const btype = u32(buf, off, little);
    const blen = u32(buf, off + 4, little);
    if (blen < 12 || off + blen > buf.length) {
      stats.tailIncomplete = true;
      break;
    }
    const bodyLen = blen - 12;
    if (btype === 0x00000006) {
      // Enhanced Packet Block
      if (bodyLen < 20) {
        stats.tailIncomplete = true;
        break;
      }
      const iface = u32(buf, off + 8, little);
      const tsHi = u32(buf, off + 12, little);
      const tsLo = u32(buf, off + 16, little);
      const capLen = u32(buf, off + 20, little);
      const origLen = u32(buf, off + 24, little);
      const tsRaw = tsHi * 4294967296 + tsLo;
      records.push({
        time: tsRaw / tsResolu,
        data: buf.subarray(off + 28, off + 28 + capLen),
        wirelen: origLen,
      });
      stats.recordCount += 1;
      if (origLen - capLen >= TRUNC_MIN_BYTES) {
        stats.truncatedRecords += 1;
        stats.minCapturedTrunc =
          stats.minCapturedTrunc === null
            ? capLen
            : Math.min(stats.minCapturedTrunc, capLen);
      }
      void iface;
    } else if (btype === 0x00000001) {
      // Interface Description Block: linktype(2)+reserved(2)+snaplen(4)
      if (bodyLen >= 8) {
        const snaplen = u32(buf, off + 8 + 4, little);
        if (stats.snaplen === null && snaplen) stats.snaplen = snaplen;
      }
    } else if (btype === 0x00000003) {
      // Simple Packet Block：无原始长度
      stats.recordCount += 1;
    }
    off += blen;
    first = false;
    void first;
  }
  return { records, stats };
}

export function buildIntegrity(fileStats: {
  allPackets?: number;
  truncated?: number;
  truncatedRtp?: number;
  maxMissingBytes?: number;
  fileCut?: boolean;
  snaplen?: number | null;
  headerTruncated?: number | null;
  tailIncomplete?: boolean;
  minCapturedTrunc?: number | null;
}): CaptureIntegrityResult {
  const headerTruncated = fileStats.headerTruncated ?? null;
  const trunc =
    headerTruncated !== null ? headerTruncated : fileStats.truncated || 0;
  const fileCut = !!fileStats.fileCut || !!fileStats.tailIncomplete;
  const rtpN =
    headerTruncated !== null
      ? Math.min(fileStats.truncatedRtp || 0, trunc)
      : fileStats.truncatedRtp || 0;

  const out: CaptureIntegrityResult = {
    status: 'ok',
    notes: [],
    allPackets: fileStats.allPackets || 0,
    truncated: trunc,
    truncatedRtp: rtpN,
    maxMissingBytes: fileStats.maxMissingBytes || 0,
    fileCut,
    snaplen: fileStats.snaplen ?? null,
  };
  const notes: string[] = [];
  if (trunc) {
    const scope = rtpN ? `（其中 RTP 媒体包 ${rtpN} 个）` : '';
    let snap = '';
    if (out.snaplen && fileStats.minCapturedTrunc === out.snaplen) {
      snap = `，抓包快照长度 ${out.snaplen} 字节`;
    }
    notes.push(
      `${trunc} 个包在捕获时被截短${scope}${snap}，最多缺失 ${out.maxMissingBytes} 字节——这类包的载荷不完整，媒体重建的对应片段会缺内容`,
    );
  }
  if (fileCut) {
    notes.push(
      '抓包文件在最后一个包的中途结束（抓包被强制终止或文件传输出错），文件尾部的数据不完整',
    );
  }
  out.notes = notes;
  out.status = notes.length ? 'warn' : 'ok';
  return out;
}

/** 多份抓包的完整性汇总：有任何警告即返回逐文件条目供前端渲染 */
export function mergeIntegrity(
  items: { role: string; filename: string; integrity: CaptureIntegrityResult }[],
): { files: { role: string; filename: string; notes: string[] }[] } | null {
  const warned = items
    .filter((it) => it.integrity?.status === 'warn')
    .map((it) => ({
      role: it.role,
      filename: it.filename,
      notes: it.integrity.notes || [],
    }));
  return warned.length ? { files: warned } : null;
}
