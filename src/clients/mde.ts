import { z } from 'zod';

import type { ContinuationTokenStore } from './continuationTokens.js';
import type { MicrosoftHttpClient } from './http.js';

const mdeEntitySchema = z.looseObject({ id: z.string() });
const mdePageSchema = z.looseObject({
  value: z.array(mdeEntitySchema),
  '@odata.nextLink': z.string().url().optional(),
});

export type MdeEntity = z.infer<typeof mdeEntitySchema>;
export interface MdePage {
  value: MdeEntity[];
  continuationToken?: string;
}

interface PageRequest {
  top: number;
  continuationToken?: string;
}

export interface VulnerabilityFilters extends PageRequest {
  severity?: string;
  cveId?: string;
}

export interface DeviceFilters extends PageRequest {
  riskScore?: string;
  exposureLevel?: string;
  osPlatform?: string;
  name?: string;
}

export class MdeClient {
  readonly #http: MicrosoftHttpClient;
  readonly #continuations: ContinuationTokenStore;

  constructor(http: MicrosoftHttpClient, continuations: ContinuationTokenStore) {
    this.#http = http;
    this.#continuations = continuations;
  }

  listVulnerabilities(filters: VulnerabilityFilters): Promise<MdePage> {
    const clauses: string[] = [];
    if (filters.severity !== undefined)
      clauses.push(`severity eq '${odataString(filters.severity)}'`);
    if (filters.cveId !== undefined) clauses.push(`id eq '${odataString(filters.cveId)}'`);
    return this.#list('/api/vulnerabilities', filters, clauses);
  }

  listVulnerableDevices(cveId: string, request: PageRequest): Promise<MdePage> {
    return this.#list(
      `/api/vulnerabilities/${encodeURIComponent(cveId)}/machineReferences`,
      request,
    );
  }

  listDevices(filters: DeviceFilters): Promise<MdePage> {
    const clauses: string[] = [];
    if (filters.riskScore !== undefined)
      clauses.push(`riskScore eq '${odataString(filters.riskScore)}'`);
    if (filters.exposureLevel !== undefined)
      clauses.push(`exposureLevel eq '${odataString(filters.exposureLevel)}'`);
    if (filters.osPlatform !== undefined)
      clauses.push(`osPlatform eq '${odataString(filters.osPlatform)}'`);
    if (filters.name !== undefined)
      clauses.push(`computerDnsName eq '${odataString(filters.name)}'`);
    return this.#list('/api/machines', filters, clauses);
  }

  async getDevice(id: string): Promise<{ device: MdeEntity; vulnerabilities: MdeEntity[] }> {
    const encodedId = encodeURIComponent(id);
    const [device, vulnerabilities] = await Promise.all([
      this.#http.request({
        path: `/api/machines/${encodedId}`,
        method: 'GET',
        family: 'mde',
        schema: mdeEntitySchema,
      }),
      this.#http.request({
        path: `/api/machines/${encodedId}/vulnerabilities`,
        method: 'GET',
        family: 'mde',
        schema: mdePageSchema,
      }),
    ]);
    return { device, vulnerabilities: vulnerabilities.value };
  }

  listSoftware(request: PageRequest): Promise<MdePage> {
    return this.#list('/api/software', request);
  }

  listSecurityRecommendations(request: PageRequest): Promise<MdePage> {
    return this.#list('/api/recommendations', request);
  }

  async #list(
    endpoint: string,
    request: PageRequest,
    filterClauses: readonly string[] = [],
  ): Promise<MdePage> {
    const path =
      request.continuationToken === undefined
        ? `${endpoint}?${buildQuery(request.top, filterClauses).toString()}`
        : this.#continuations.redeem(request.continuationToken);
    const page = await this.#http.request({
      path,
      method: 'GET',
      family: 'mde',
      schema: mdePageSchema,
    });
    const nextLink = page['@odata.nextLink'];
    return {
      value: page.value,
      ...(nextLink === undefined ? {} : { continuationToken: this.#continuations.issue(nextLink) }),
    };
  }
}

function buildQuery(top: number, clauses: readonly string[]): URLSearchParams {
  const query = new URLSearchParams({ $top: String(top) });
  if (clauses.length > 0) query.set('$filter', clauses.join(' and '));
  return query;
}

function odataString(value: string): string {
  return value.replaceAll("'", "''");
}
