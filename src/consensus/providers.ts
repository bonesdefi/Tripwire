import {
  fetchWithRetry,
  packetMessage,
  parseVerdict,
  type VerifierClient,
  type VerifierFactory,
  type VerifyInput,
} from './verifier.js';
import type { Verdict } from './types.js';

/**
 * Provider clients: thin fetch wrappers, keys via env, strict verdict
 * parsing. No SDKs, no LLM frameworks — minimal, auditable supply chain.
 */

function requireKey(env: string): string {
  const key = process.env[env];
  if (key === undefined || key === '') {
    throw new Error(`missing ${env} for verifier provider`);
  }
  return key;
}

async function readBodyError(response: Response): Promise<string> {
  const body = (await response.text().catch(() => '')).slice(0, 200);
  return `HTTP ${response.status}${body === '' ? '' : `: ${body}`}`;
}

export class AnthropicVerifier implements VerifierClient {
  readonly id: string;
  constructor(private readonly model: string) {
    this.id = `anthropic/${model}`;
  }

  async verify({ packet, prompt, timeoutMs }: VerifyInput): Promise<Verdict> {
    const response = await fetchWithRetry(
      'https://api.anthropic.com/v1/messages',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': requireKey('ANTHROPIC_API_KEY'),
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: 1024,
          system: prompt.system,
          messages: [{ role: 'user', content: packetMessage(packet) }],
        }),
      },
      timeoutMs,
    );
    if (!response.ok) throw new Error(await readBodyError(response));
    const data = (await response.json()) as { content?: { type: string; text?: string }[] };
    const text = data.content?.find((b) => b.type === 'text')?.text ?? '';
    return parseVerdict(text);
  }
}

export class OpenAiVerifier implements VerifierClient {
  readonly id: string;
  constructor(private readonly model: string) {
    this.id = `openai/${model}`;
  }

  async verify({ packet, prompt, timeoutMs }: VerifyInput): Promise<Verdict> {
    const response = await fetchWithRetry(
      'https://api.openai.com/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${requireKey('OPENAI_API_KEY')}`,
        },
        body: JSON.stringify({
          model: this.model,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: packetMessage(packet) },
          ],
        }),
      },
      timeoutMs,
    );
    if (!response.ok) throw new Error(await readBodyError(response));
    const data = (await response.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    return parseVerdict(data.choices?.[0]?.message?.content ?? '');
  }
}

export class GoogleVerifier implements VerifierClient {
  readonly id: string;
  constructor(private readonly model: string) {
    this.id = `google/${model}`;
  }

  async verify({ packet, prompt, timeoutMs }: VerifyInput): Promise<Verdict> {
    const key = process.env['GEMINI_API_KEY'] ?? process.env['GOOGLE_API_KEY'];
    if (key === undefined || key === '') {
      throw new Error('missing GEMINI_API_KEY (or GOOGLE_API_KEY) for verifier provider');
    }
    const response = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(this.model)}:generateContent`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-goog-api-key': key },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: prompt.system }] },
          contents: [{ role: 'user', parts: [{ text: packetMessage(packet) }] }],
          generationConfig: { responseMimeType: 'application/json' },
        }),
      },
      timeoutMs,
    );
    if (!response.ok) throw new Error(await readBodyError(response));
    const data = (await response.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
    };
    const text = data.candidates?.[0]?.content?.parts?.map((p) => p.text ?? '').join('') ?? '';
    return parseVerdict(text);
  }
}

/**
 * Default factory: `provider/model` -> client. Construction is cheap and
 * key-less; a missing API key surfaces as a verify-time error, which
 * fail-closed aggregation turns into a failed verdict.
 */
export const defaultVerifierFactory: VerifierFactory = (id: string) => {
  const slash = id.indexOf('/');
  const provider = slash === -1 ? id : id.slice(0, slash);
  const model = slash === -1 ? '' : id.slice(slash + 1);
  if (model === '') throw new Error(`invalid panel entry "${id}" (expected provider/model)`);
  switch (provider) {
    case 'anthropic':
      return new AnthropicVerifier(model);
    case 'openai':
      return new OpenAiVerifier(model);
    case 'google':
      return new GoogleVerifier(model);
    default:
      throw new Error(`unknown verifier provider "${provider}" in panel entry "${id}"`);
  }
};
