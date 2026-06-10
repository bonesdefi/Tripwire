import { describe, expect, it } from 'vitest';

import { extractForms, normalForms } from '../src/provenance/extract.js';

describe('normalForms', () => {
  it('normalizes strings to lowercase trimmed forms', () => {
    expect(normalForms('  Acme Corp  ')).toContain('s:acme corp');
  });

  it('normalizes hex values case-insensitively with and without 0x prefix', () => {
    const prefixed = normalForms('0xAAAA00000000000000000000000000000000AAAA');
    const bare = normalForms('aaaa00000000000000000000000000000000aaaa');
    const lower = normalForms('0xaaaa00000000000000000000000000000000aaaa');
    const hexForm = 'h:aaaa00000000000000000000000000000000aaaa';
    expect(prefixed).toContain(hexForm);
    expect(bare).toContain(hexForm);
    expect(lower).toContain(hexForm);
  });

  it('normalizes numbers and numeric strings to the same form', () => {
    expect(normalForms(12500)).toEqual(['n:12500']);
    expect(normalForms('12500')).toContain('n:12500');
    expect(normalForms('12,500')).toContain('n:12500');
    expect(normalForms('12_500')).toContain('n:12500');
    expect(normalForms('12500.00')).toContain('n:12500');
    expect(normalForms(-0)).toEqual(['n:0']);
  });

  it('returns nothing for empty or non-finite values', () => {
    expect(normalForms('')).toEqual([]);
    expect(normalForms('   ')).toEqual([]);
    expect(normalForms(Infinity)).toEqual([]);
    expect(normalForms(NaN)).toEqual([]);
  });

  it('does not conflate value classes', () => {
    // "12500" the string also has an s: form, but plain words never gain n:/h: forms.
    expect(normalForms('hello')).toEqual(['s:hello']);
    // hex-looking and number-looking are tagged distinctly
    expect(normalForms('123456')).toEqual(
      expect.arrayContaining(['s:123456', 'h:123456', 'n:123456']),
    );
  });
});

describe('extractForms', () => {
  it('finds 0x addresses embedded in prose', () => {
    const forms = extractForms({
      content: [
        {
          type: 'text',
          text: 'remit payment to our new treasury wallet: 0xBBBB00000000000000000000000000000000BBBB today',
        },
      ],
    });
    expect(forms).toContain('h:bbbb00000000000000000000000000000000bbbb');
  });

  it('finds bare hex runs of 16+ chars but not short hex words', () => {
    const forms = extractForms('id deadbeefdeadbeef and the word dead');
    expect(forms).toContain('h:deadbeefdeadbeef');
    expect([...forms].some((f) => f === 'h:dead')).toBe(false);
  });

  it('finds emails and URLs', () => {
    const forms = extractForms('contact Billing@Acme.example or https://acme.example/Pay?x=1');
    expect(forms).toContain('s:billing@acme.example');
    expect(forms).toContain('s:https://acme.example/pay?x=1');
  });

  it('finds comma-formatted amounts in text', () => {
    const forms = extractForms('Amount due: 12,500 USDC by 2026-06-15');
    expect(forms).toContain('n:12500');
  });

  it('finds id-like tokens', () => {
    const forms = extractForms('see invoice-acme-7741 and tx_0001 and V-1001');
    expect(forms).toContain('s:invoice-acme-7741');
    expect(forms).toContain('s:tx_0001');
    expect(forms).toContain('s:v-1001');
  });

  it('indexes number leaves and walks nested structures', () => {
    const forms = extractForms({
      a: [{ b: 12500 }, 'wallet 0xAAAA00000000000000000000000000000000AAAA'],
    });
    expect(forms).toContain('n:12500');
    expect(forms).toContain('h:aaaa00000000000000000000000000000000aaaa');
  });

  it('does not index object keys', () => {
    const forms = extractForms({ secretkeyname: 'v' });
    expect(forms).toContain('s:v');
    expect(forms).not.toContain('s:secretkeyname');
  });

  it('skips whole-string indexing for very long strings but keeps tokens', () => {
    const long = `${'x'.repeat(600)} 0xCCCC00000000000000000000000000000000CCCC`;
    const forms = extractForms(long);
    expect(forms).toContain('h:cccc00000000000000000000000000000000cccc');
    expect([...forms].some((f) => f.startsWith('s:xxxx'))).toBe(false);
  });

  it('extracts JSON-embedded values exactly as a tool result carries them', () => {
    // Shape of a real receipted result: JSON inside a text content block.
    const vendor = {
      id: 'V-1001',
      wallet: '0xAAAA00000000000000000000000000000000AAAA',
      email: 'billing@acme.example',
    };
    const forms = extractForms({
      content: [{ type: 'text', text: JSON.stringify(vendor, null, 2) }],
    });
    expect(forms).toContain('h:aaaa00000000000000000000000000000000aaaa');
    expect(forms).toContain('s:billing@acme.example');
    expect(forms).toContain('s:v-1001');
  });
});
