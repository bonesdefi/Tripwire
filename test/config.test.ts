import { describe, expect, it } from 'vitest';

import { ConfigError, parseConfig } from '../src/policy/config.js';
import { parseNamespacedTool } from '../src/proxy/proxy.js';

describe('parseConfig', () => {
  it('parses a minimal config and applies safe defaults', () => {
    const config = parseConfig(`
upstreams:
  - name: vendors
    command: ["node", "server.js"]
`);
    expect(config.upstreams).toHaveLength(1);
    expect(config.upstreams[0]).toMatchObject({
      name: 'vendors',
      command: ['node', 'server.js'],
      trust: 'untrusted', // safe default: trust must be opted into
      env: {},
    });
    expect(config.state_dir).toBe('.tripwire');
  });

  it('accepts explicit trust labels and env', () => {
    const config = parseConfig(`
upstreams:
  - name: vendors
    command: ["node", "server.js"]
    trust: trusted
    env: { LOG_LEVEL: debug }
state_dir: /tmp/tw
`);
    expect(config.upstreams[0]?.trust).toBe('trusted');
    expect(config.upstreams[0]?.env).toEqual({ LOG_LEVEL: 'debug' });
    expect(config.state_dir).toBe('/tmp/tw');
  });

  it('rejects upstream names containing underscores (namespace delimiter)', () => {
    expect(() =>
      parseConfig(`
upstreams:
  - name: vendor_db
    command: ["node", "server.js"]
`),
    ).toThrow(/no underscores/);
  });

  it('rejects duplicate upstream names', () => {
    expect(() =>
      parseConfig(`
upstreams:
  - name: a
    command: ["x"]
  - name: a
    command: ["y"]
`),
    ).toThrow(/duplicate upstream name/);
  });

  it('rejects empty upstream lists, empty commands, and bad trust values', () => {
    expect(() => parseConfig('upstreams: []')).toThrow(ConfigError);
    expect(() =>
      parseConfig(`
upstreams:
  - name: a
    command: []
`),
    ).toThrow(ConfigError);
    expect(() =>
      parseConfig(`
upstreams:
  - name: a
    command: ["x"]
    trust: kinda
`),
    ).toThrow(ConfigError);
  });

  it('rejects invalid YAML with the source in the message', () => {
    expect(() => parseConfig('upstreams: [', 'my.yaml')).toThrow(/my\.yaml: invalid YAML/);
  });
});

describe('parseNamespacedTool', () => {
  it('splits at the first double underscore', () => {
    expect(parseNamespacedTool('vendors__get_vendor')).toEqual({
      upstream: 'vendors',
      tool: 'get_vendor',
    });
    // Tool names may themselves contain `__`; upstream names cannot.
    expect(parseNamespacedTool('a__b__c')).toEqual({ upstream: 'a', tool: 'b__c' });
  });

  it('rejects names without a namespace', () => {
    expect(parseNamespacedTool('plain_tool')).toBeUndefined();
    expect(parseNamespacedTool('__leading')).toBeUndefined();
    expect(parseNamespacedTool('trailing__')).toBeUndefined();
    expect(parseNamespacedTool('')).toBeUndefined();
  });
});
