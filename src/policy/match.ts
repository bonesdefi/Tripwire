/**
 * Policy rule matching. First matching rule wins.
 *
 * Glob support is implemented here rather than via a dependency: this is
 * the code adversaries will probe, and the supply-chain surface stays
 * minimal. `*` matches any run of characters (including none); `?` matches
 * exactly one. Everything else is literal.
 */

export interface RuleMatch {
  tool?: string | undefined;
  upstream?: string | undefined;
  annotation?: Record<string, boolean | string | number> | undefined;
}

export interface MatchContext {
  /** Fully namespaced tool name, e.g. `payments__send_payment`. */
  tool: string;
  upstream: string;
  annotations?: Record<string, unknown> | undefined;
}

const REGEX_SPECIALS = /[.+^${}()|[\]\\]/g;

export function globToRegExp(glob: string): RegExp {
  let pattern = '';
  for (const ch of glob) {
    if (ch === '*') pattern += '.*';
    else if (ch === '?') pattern += '.';
    else pattern += ch.replace(REGEX_SPECIALS, '\\$&');
  }
  return new RegExp(`^${pattern}$`);
}

export function matchesRule(match: RuleMatch, ctx: MatchContext): boolean {
  if (match.tool !== undefined && !globToRegExp(match.tool).test(ctx.tool)) {
    return false;
  }
  if (match.upstream !== undefined && match.upstream !== ctx.upstream) {
    return false;
  }
  if (match.annotation !== undefined) {
    const annotations = ctx.annotations ?? {};
    for (const [key, expected] of Object.entries(match.annotation)) {
      if (annotations[key] !== expected) return false;
    }
  }
  return true;
}

/** Return the first rule whose match clause accepts the context. */
export function findRule<R extends { match: RuleMatch }>(
  rules: readonly R[],
  ctx: MatchContext,
): R | undefined {
  return rules.find((rule) => matchesRule(rule.match, ctx));
}
