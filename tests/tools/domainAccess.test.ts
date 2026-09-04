import { describe, expect, it } from 'vitest';

import {
  alertStatusSchema,
  graphSeveritySchema,
  incidentStatusSchema,
  validateGraphAccess,
} from '../../src/tools/incidents.js';
import {
  exposureLevelSchema,
  riskScoreSchema,
  validateMdeAccess,
  vulnerabilitySeveritySchema,
} from '../../src/tools/vulns.js';

describe('domain tool authentication gates', () => {
  it('returns the explicit Graph activation action when interaction is required', () => {
    expect(validateGraphAccess({ id: '1' }, false)).toEqual({
      ok: false,
      reason:
        'Microsoft Graph requires interactive sign-in. Run `node dist/index.js --sign-in` in a terminal, or call get_connection_status, then retry.',
    });
  });

  it('reports MDE activation separately from Graph', () => {
    expect(validateMdeAccess({ id: 'machine-1' }, false)).toEqual({
      ok: false,
      reason:
        'Defender for Endpoint requires interactive sign-in. Run `node dist/index.js --sign-in` in a terminal, or call get_connection_status, then retry.',
    });
  });

  it('enforces Microsoft Graph lowercase severity and endpoint-specific statuses', () => {
    expect(graphSeveritySchema.safeParse('high').success).toBe(true);
    expect(graphSeveritySchema.safeParse('High').success).toBe(false);
    expect(incidentStatusSchema.safeParse('active').success).toBe(true);
    expect(incidentStatusSchema.safeParse('new').success).toBe(false);
    expect(alertStatusSchema.safeParse('new').success).toBe(true);
    expect(alertStatusSchema.safeParse('active').success).toBe(false);
  });

  it('enforces Defender for Endpoint capitalised enum values', () => {
    expect(vulnerabilitySeveritySchema.safeParse('Critical').success).toBe(true);
    expect(vulnerabilitySeveritySchema.safeParse('critical').success).toBe(false);
    expect(riskScoreSchema.safeParse('Informational').success).toBe(true);
    expect(riskScoreSchema.safeParse('informational').success).toBe(false);
    expect(exposureLevelSchema.safeParse('High').success).toBe(true);
    expect(exposureLevelSchema.safeParse('high').success).toBe(false);
  });
});
