import { parseIsoDurationSeconds } from '../config.js';

export interface KqlValidationConfig {
  defaultTimespan: string;
  maxTimespan: string;
  maxRows: number;
}

export type KqlValidationResult =
  | { ok: true; query: string; timespan: string; notices: readonly string[] }
  | { ok: false; reason: string };

const EXTERNAL_ACCESS_IDENTIFIERS = new Set([
  'externaldata',
  'externaltable',
  'externaldatatable',
  'inlineexternaltable',
  'adx',
  'cluster',
  'database',
]);

export function validateKql(
  query: unknown,
  timespan: unknown,
  config: KqlValidationConfig,
): KqlValidationResult {
  if (typeof query !== 'string' || query.trim().length === 0) {
    return { ok: false, reason: 'The KQL query must be a non-empty string.' };
  }

  const stripped = stripStringsAndComments(query);
  if (!stripped.ok) return stripped;
  const visibleQuery = stripped.query;
  const tokens = [...visibleQuery.matchAll(/[a-zA-Z0-9_]+|\[\s*\](?=\s*\()|[^\s]/g)].map(
    (match) => {
      const token = match[0];
      // The scanner masks quoted names too. Recover only bracketed call names,
      // using the original offsets, so dynamic-array string values stay masked.
      const identifier = token.startsWith('[')
        ? bracketedCallName(query.slice(match.index, match.index + token.length))
        : token;
      return identifier.toLowerCase().replaceAll('_', '');
    },
  );
  let evaluating = false;
  for (const token of tokens) {
    if (token === 'evaluate') evaluating = true;
    if (token === '(' || token === '|' || token === ';') evaluating = false;
    if (EXTERNAL_ACCESS_IDENTIFIERS.has(token) || (evaluating && /request(?:post)?$/.test(token))) {
      return {
        ok: false,
        reason: `External data access (${token}) is not allowed. Use a Defender XDR table instead.`,
      };
    }
  }

  const requestedTimespan = timespan ?? config.defaultTimespan;
  if (typeof requestedTimespan !== 'string') {
    return { ok: false, reason: 'The timespan must be a valid ISO 8601 duration.' };
  }
  const requestedSeconds = parseIsoDurationSeconds(requestedTimespan);
  const maximumSeconds = parseIsoDurationSeconds(config.maxTimespan);
  if (requestedSeconds === null || maximumSeconds === null) {
    return { ok: false, reason: 'The timespan must be a valid ISO 8601 duration.' };
  }

  const notices: string[] = [];
  const effectiveTimespan =
    requestedSeconds > maximumSeconds ? config.maxTimespan : requestedTimespan;
  if (requestedSeconds > maximumSeconds) {
    notices.push(
      `Requested timespan ${requestedTimespan} exceeded the configured maximum and was clamped to ${config.maxTimespan}.`,
    );
  }
  if (/\bunion\s+\*/i.test(visibleQuery) && !/\b(?:where|filter)\b/i.test(visibleQuery)) {
    notices.push(
      'The query contains `union *`, which may scan an unexpectedly broad dataset. Add table names, filters, or a shorter timespan where possible.',
    );
  }

  const rowOperators = [
    ...outerResultStatement(visibleQuery).matchAll(/(?:^|\|)\s*(?:take|limit|top)\s+(\d+)\b/gi),
  ];
  const alreadyBounded = rowOperators.some((match) => Number(match[1]) <= config.maxRows);
  const renderPipeIndex = trailingOuterRenderPipeIndex(visibleQuery);
  const guardedQuery = alreadyBounded
    ? query
    : renderPipeIndex === undefined
      ? `${query.trimEnd()}\n| take ${config.maxRows}`
      : `${query.slice(0, renderPipeIndex).trimEnd()}\n| take ${config.maxRows} ${query.slice(renderPipeIndex)}`;
  if (!alreadyBounded) {
    notices.push(`The query was capped at ${config.maxRows} rows.`);
  }

  return { ok: true, query: guardedQuery, timespan: effectiveTimespan, notices };
}

function bracketedCallName(token: string): string {
  const parts: string[] = [];
  // Reuse the same scanner for comments and adjacent literals in quoted names.
  stripStringsAndComments(token, (literal) => {
    if (literal.startsWith('```')) {
      parts.push(literal.slice(3, -3));
      return;
    }
    const content = literal.replace(/^[hH]?@?['"]|['"]$/g, '');
    if (/^[hH]?@/.test(literal)) {
      const quote = literal.at(-1)!;
      parts.push(content.replaceAll(quote + quote, quote));
      return;
    }
    // Kusto uses fixed-width hex escapes and up to three octal digits.
    parts.push(
      content.replace(
        /\\(u[\da-fA-F]{4}|x[\da-fA-F]{2}|[0-9]{1,3}|[\s\S])/g,
        (_, escape: string) => {
          if (escape.startsWith('u') || escape.startsWith('x')) {
            return String.fromCharCode(Number.parseInt(escape.slice(1), 16));
          }
          if (/^[0-9]/.test(escape)) {
            return String.fromCharCode(Number.parseInt(escape, 8));
          }
          return /^[abfnrtv]$/.test(escape) ? ' ' : escape;
        },
      ),
    );
  });
  return parts.join('');
}

function trailingOuterRenderPipeIndex(query: string): number | undefined {
  let depth = 0;
  let pipeIndex: number | undefined;

  for (let index = 0; index < query.length; index += 1) {
    const character = query[index];
    if (character === '(' || character === '[' || character === '{') {
      depth += 1;
      continue;
    }
    if (character === ')' || character === ']' || character === '}') {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (character === ';' && depth === 0) {
      pipeIndex = undefined;
      continue;
    }
    if (character === '|' && depth === 0) {
      pipeIndex = index;
    }
  }

  if (pipeIndex === undefined) return undefined;
  return /^\s*render\b/i.test(query.slice(pipeIndex + 1)) ? pipeIndex : undefined;
}

function outerResultStatement(query: string): string {
  let result = '';
  let depth = 0;

  for (const character of query) {
    if (character === '(' || character === '[' || character === '{') {
      depth += 1;
      result += ' ';
      continue;
    }
    if (character === ')' || character === ']' || character === '}') {
      depth = Math.max(0, depth - 1);
      result += ' ';
      continue;
    }
    if (character === ';' && depth === 0) {
      result = '';
      continue;
    }
    result += depth === 0 ? character : character === '\n' ? '\n' : ' ';
  }

  return result;
}

type StripResult = { ok: true; query: string } | { ok: false; reason: string };

type ScannerState =
  | 'code'
  | 'line-comment'
  | 'standard-single'
  | 'standard-double'
  | 'verbatim-single'
  | 'verbatim-double'
  | 'multiline';

function stripStringsAndComments(
  query: string,
  onLiteral?: (literal: string) => void,
): StripResult {
  let result = '';
  let index = 0;
  let state: ScannerState = 'code';
  let literalIndex = 0;

  while (index < query.length) {
    const current = query[index] ?? '';
    const next = query[index + 1] ?? '';
    if (state === 'code') {
      if (current === '/' && next === '/') {
        state = 'line-comment';
        result += mask(query.slice(index, index + 2));
        index += 2;
        continue;
      }
      if (query.startsWith('```', index)) {
        literalIndex = index;
        state = 'multiline';
        result += '   ';
        index += 3;
        continue;
      }
      const literal = literalStart(query, index);
      if (literal !== undefined) {
        literalIndex = index;
        state = literal.state;
        result += mask(query.slice(index, index + literal.length));
        index += literal.length;
        continue;
      }
      result += current;
      index += 1;
      continue;
    }

    if (state === 'line-comment') {
      if (current === '\n') {
        state = 'code';
        result += '\n';
      } else {
        result += ' ';
      }
      index += 1;
      continue;
    }

    if (state === 'multiline') {
      if (query.startsWith('```', index)) {
        onLiteral?.(query.slice(literalIndex, index + 3));
        state = 'code';
        result += '   ';
        index += 3;
      } else {
        result += current === '\n' ? '\n' : ' ';
        index += 1;
      }
      continue;
    }

    const quote = state.endsWith('single') ? "'" : '"';
    const verbatim = state.startsWith('verbatim');
    if (!verbatim && current === '\\' && index + 1 < query.length) {
      result += mask(query.slice(index, index + 2));
      index += 2;
      continue;
    }
    if (verbatim && current === quote && next === quote) {
      result += '  ';
      index += 2;
      continue;
    }
    if (current === quote) {
      onLiteral?.(query.slice(literalIndex, index + 1));
      state = 'code';
    }
    result += ' ';
    index += 1;
  }

  if (state !== 'code' && state !== 'line-comment') {
    return {
      ok: false,
      reason: 'The KQL query contains an unterminated string literal. Close the literal and retry.',
    };
  }
  return { ok: true, query: result };
}

function literalStart(
  query: string,
  index: number,
):
  | { state: Exclude<ScannerState, 'code' | 'line-comment' | 'multiline'>; length: number }
  | undefined {
  const candidate = query.slice(index, index + 3);
  const obfuscated = candidate[0]?.toLowerCase() === 'h';
  const prefixLength = obfuscated ? 1 : 0;
  const verbatim = candidate[prefixLength] === '@';
  const quoteIndex = prefixLength + (verbatim ? 1 : 0);
  const quote = candidate[quoteIndex];
  if (quote !== "'" && quote !== '"') return undefined;
  return {
    state: `${verbatim ? 'verbatim' : 'standard'}-${quote === "'" ? 'single' : 'double'}`,
    length: quoteIndex + 1,
  };
}

function mask(value: string): string {
  return value.replace(/[^\n]/g, ' ');
}
