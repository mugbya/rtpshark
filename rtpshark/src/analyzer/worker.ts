// 分析 Worker：大抓包的解析与分析在后台线程执行，避免阻塞 UI
import { uploadPhase, analyzePhase } from './pipeline';
import type { AnalyzeParams, UploadFileInput } from './pipeline';

export interface WorkerRequest {
  id: number;
  type: 'upload' | 'analyze';
  files?: (Omit<UploadFileInput, 'bytes'> & { bytes: ArrayBuffer })[];
  session?: UploadFileInput[];
  upload?: unknown;
  params?: AnalyzeParams;
}

export interface WorkerResponse {
  id: number;
  type: 'progress' | 'upload' | 'analyze' | 'error';
  stage?: string;
  payload?: unknown;
  error?: string;
}

self.onmessage = (ev: MessageEvent<WorkerRequest>) => {
  const req = ev.data;
  const post = (msg: WorkerResponse) => (self as unknown as Worker).postMessage(msg);
  try {
    if (req.type === 'upload') {
      post({ id: req.id, type: 'progress', stage: '正在解析抓包文件…' });
      const files = (req.files || []).map((f) => ({
        ...f,
        bytes: new Uint8Array(f.bytes),
      }));
      const session = uploadPhase(files);
      // 会话原始字节不回传主线程，留在 worker 内存里供 analyze 使用
      sessionStore = session;
      const uploadView = {
        ...session,
        files: session.files.map((f) => ({ role: f.role, filename: f.filename })),
      };
      post({ id: req.id, type: 'upload', payload: uploadView });
    } else if (req.type === 'analyze') {
      post({ id: req.id, type: 'progress', stage: '正在分析…' });
      const out = analyzePhase(sessionStore!, req.params!);
      post({ id: req.id, type: 'analyze', payload: out });
    }
  } catch (e) {
    post({ id: req.id, type: 'error', error: e instanceof Error ? e.message : String(e) });
  }
};

import type { UploadSession } from './pipeline';
let sessionStore: UploadSession | null = null;
