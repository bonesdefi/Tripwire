import type { CheckPrompt, Verdict, VerificationPacket } from './types.js';
import { VerdictSchema } from './types.js';

/**
 * Verifier client interface and strict verdict parsing.
 *
 * Implementations are thin fetch wrappers (no LLM framework dependency).
 * A verifier that times out, errors, or returns anything that does not
 * parse into a strict Verdict counts as a FAILED verdict under fail-closed
 * aggregation — see panel.ts.
 */

export interface VerifyInput {
  packet: VerificationPacket;
  prompt: CheckPrompt;
  timeoutMs: number;
}

export interface VerifierClient {
  /** `provider/model`, e.g. `anthropic/claude-sonnet-latest`. */
  readonly id: string;
  verify(input: VerifyInput): Promise<Verdict>;
}

/** Construct a verifier from a `provider/model` panel entry. */
export type VerifierFactory = (id: string) => VerifierClient;

export class VerdictParseError extends Error {
  constructor(message: string) {
    super(`verdict parse failed: ${message}`);
    this.name = 'VerdictParseError';
  }
}

/**
 * Parse a model response into a strict Verdict. Accepts a bare JSON object
 * or one wrapped in a markdown code fence (a common provider tic); anything
 * else is rejected.
 */
export function parseVerdict(text: string): Verdict {
  const trimmed = text.trim();
  const candidates = [trimmed];
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/m.exec(trimmed);
  if (fenced?.[1] !== undefined) candidates.push(fenced[1].trim());

  for (const candidate of candidates) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(candidate);
    } catch {
      continue;
    }
    const result = VerdictSchema.safeParse(parsed);
    if (result.success) return result.data;
    throw new VerdictParseError(
      result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '),
    );
  }
  throw new VerdictParseError('response is not a JSON object');
}

/** The user message a verifier receives: the packet as fenced JSON data. */
export function packetMessage(packet: VerificationPacket): string {
  return `Verification packet:\n\`\`\`json\n${JSON.stringify(packet, null, 2)}\n\`\`\``;
}

/**
 * fetch with timeout and a single retry on network failure / 5xx.
 * Every external call Tripwire makes goes through this.
 */
export async function fetchWithRetry(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (response.status >= 500 && attempt === 0) {
        lastError = new Error(`HTTP ${response.status}`);
        continue;
      }
      return response;
    } catch (err) {
      lastError = err;
      // Do not retry an abort: the time budget is already spent.
      if (err instanceof DOMException && err.name === 'TimeoutError') break;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
