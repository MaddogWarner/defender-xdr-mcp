export const GRAPH_SCOPES = [
  'https://graph.microsoft.com/ThreatHunting.Read.All',
  'https://graph.microsoft.com/SecurityIncident.Read.All',
  'https://graph.microsoft.com/SecurityAlert.Read.All',
  'https://graph.microsoft.com/User.Read',
] as const;

export const MDE_TOKEN_SCOPES = ['https://api.securitycenter.microsoft.com/.default'] as const;

export const MDE_DELEGATED_PERMISSIONS = [
  'Vulnerability.Read',
  'Machine.Read',
  'Software.Read',
  'SecurityRecommendation.Read',
] as const;
