import { z } from 'zod';

import type { ContinuationTokenStore } from './continuationTokens.js';
import type { MicrosoftHttpClient } from './http.js';

const huntingResultSchema = z.looseObject({
  schema: z.array(
    z.looseObject({
      name: z.string(),
      type: z.string(),
    }),
  ),
  results: z.array(z.record(z.string(), z.unknown())),
});

export type HuntingResult = z.infer<typeof huntingResultSchema>;

const graphEntitySchema = z.looseObject({ id: z.string() });
const graphPageSchema = z.looseObject({
  value: z.array(graphEntitySchema),
  '@odata.nextLink': z.string().url().optional(),
});

export type GraphEntity = z.infer<typeof graphEntitySchema>;
export interface GraphPage {
  value: GraphEntity[];
  continuationToken?: string;
}

export interface GraphListFilters {
  status?: string;
  severity?: string;
  assignedTo?: string;
  createdAfter?: string;
  createdBefore?: string;
  top: number;
  continuationToken?: string;
}

export class GraphClient {
  readonly #http: MicrosoftHttpClient;
  readonly #continuations: ContinuationTokenStore;

  constructor(http: MicrosoftHttpClient, continuations: ContinuationTokenStore) {
    this.#http = http;
    this.#continuations = continuations;
  }

  runHuntingQuery(query: string, timespan: string): Promise<HuntingResult> {
    return this.#http.request({
      path: '/v1.0/security/runHuntingQuery',
      method: 'POST',
      family: 'hunting',
      schema: huntingResultSchema,
      body: { Query: query, Timespan: timespan },
      timeoutMs: 210_000,
    });
  }

  listIncidents(filters: GraphListFilters): Promise<GraphPage> {
    return this.#list('/v1.0/security/incidents', filters);
  }

  getIncident(id: string): Promise<GraphEntity> {
    return this.#http.request({
      path: `/v1.0/security/incidents/${encodeURIComponent(id)}?$expand=alerts`,
      method: 'GET',
      family: 'graph-other',
      schema: graphEntitySchema,
    });
  }

  listAlerts(filters: GraphListFilters): Promise<GraphPage> {
    return this.#list('/v1.0/security/alerts_v2', filters);
  }

  getAlert(id: string): Promise<GraphEntity> {
    return this.#http.request({
      path: `/v1.0/security/alerts_v2/${encodeURIComponent(id)}`,
      method: 'GET',
      family: 'graph-other',
      schema: graphEntitySchema,
    });
  }

  async #list(endpoint: string, filters: GraphListFilters): Promise<GraphPage> {
    const path =
      filters.continuationToken === undefined
        ? `${endpoint}?${buildGraphQuery(filters).toString()}`
        : this.#continuations.redeem(filters.continuationToken);
    const page = await this.#http.request({
      path,
      method: 'GET',
      family: 'graph-other',
      schema: graphPageSchema,
    });
    const nextLink = page['@odata.nextLink'];
    return {
      value: page.value,
      ...(nextLink === undefined ? {} : { continuationToken: this.#continuations.issue(nextLink) }),
    };
  }
}

function buildGraphQuery(filters: GraphListFilters): URLSearchParams {
  const clauses: string[] = [];
  if (filters.status !== undefined) clauses.push(`status eq '${odataString(filters.status)}'`);
  if (filters.severity !== undefined)
    clauses.push(`severity eq '${odataString(filters.severity)}'`);
  if (filters.assignedTo !== undefined)
    clauses.push(`assignedTo eq '${odataString(filters.assignedTo)}'`);
  if (filters.createdAfter !== undefined)
    clauses.push(`createdDateTime ge ${filters.createdAfter}`);
  if (filters.createdBefore !== undefined)
    clauses.push(`createdDateTime le ${filters.createdBefore}`);
  const query = new URLSearchParams({ $top: String(filters.top) });
  if (clauses.length > 0) query.set('$filter', clauses.join(' and '));
  return query;
}

function odataString(value: string): string {
  return value.replaceAll("'", "''");
}
