// 主线程侧的 Worker 封装：请求/响应配对 + 进度回调
import type { AnalyzeOutput, AnalyzeParams, UploadFileInput, UploadSession } from './pipeline';

export type UploadSessionPublic = Omit<UploadSession, 'files'> & {
  files: Omit<UploadFileInput, 'bytes'>[];
};

export interface ProgressInfo {
  stage: string;
}

type Pending = {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
};

export class AnalyzerClient {
  private worker: Worker;
  private seq = 0;
  private pending = new Map<number, Pending>();
  onProgress: ((p: ProgressInfo) => void) | null = null;

  constructor() {
    this.worker = new Worker(new URL('./worker.ts', import.meta.url), {
      type: 'module',
    });
    this.worker.onmessage = (ev: MessageEvent) => {
      const msg = ev.data as {
        id: number;
        type: string;
        stage?: string;
        payload?: unknown;
        error?: string;
      };
      if (msg.type === 'progress') {
        this.onProgress?.({ stage: msg.stage || '' });
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.type === 'error') p.reject(new Error(msg.error || '未知错误'));
      else p.resolve(msg.payload);
    };
  }

  private call<T>(msg: Record<string, unknown>): Promise<T> {
    const id = ++this.seq;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.worker.postMessage({ id, ...msg });
    });
  }

  upload(
    files: { role: string; filename: string; bytes: ArrayBuffer }[],
  ): Promise<UploadSessionPublic> {
    return this.call({ type: 'upload', files });
  }

  analyze(
    session: UploadFileInput[],
    upload: unknown,
    params: AnalyzeParams,
  ): Promise<AnalyzeOutput> {
    return this.call({ type: 'analyze', session, upload, params });
  }
}
