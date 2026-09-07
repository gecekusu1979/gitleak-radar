import { Worker } from "node:worker_threads";

export interface RegexMatchResult {
  matched: boolean;
  matches: Array<{
    value: string;
    index: number;
  }>;
}

const WORKER_SCRIPT = `
  const { parentPort, workerData } = require("node:worker_threads");
  const { pattern, flags, text } = workerData;
  try {
    const regex = new RegExp(pattern, flags);
    const matches = [];

    if (regex.global) {
      let m;
      while ((m = regex.exec(text)) !== null) {
        matches.push({ value: m[0], index: m.index });
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    } else {
      const m = regex.exec(text);
      if (m) {
        matches.push({ value: m[0], index: m.index });
      }
    }

    parentPort.postMessage({ success: true, matched: matches.length > 0, matches });
  } catch (err) {
    parentPort.postMessage({ success: false, error: err.message });
  }
`;

export function runRegexWithTimeout(
  pattern: string,
  flags: string,
  text: string,
  timeoutMs: number = 250
): Promise<RegexMatchResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_SCRIPT, {
      eval: true,
      workerData: { pattern, flags, text }
    });

    let isSettled = false;

    const timer = setTimeout(() => {
      if (!isSettled) {
        isSettled = true;
        worker.terminate().finally(() => {
          reject(new Error(`Regex execution timed out after ${timeoutMs}ms (ReDoS protection).`));
        });
      }
    }, timeoutMs);

    worker.on("message", (msg) => {
      if (!isSettled) {
        isSettled = true;
        clearTimeout(timer);
        worker.terminate().finally(() => {
          if (msg.success) {
            resolve({ matched: msg.matched, matches: msg.matches });
          } else {
            reject(new Error(msg.error));
          }
        });
      }
    });

    worker.on("error", (err) => {
      if (!isSettled) {
        isSettled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
  });
}
