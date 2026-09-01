export interface HuntingTable {
  name: string;
  purpose: string;
  keyColumns: readonly string[];
}

export const HUNTING_TABLES: readonly HuntingTable[] = [
  {
    name: 'AlertInfo',
    purpose: 'Defender XDR alert metadata.',
    keyColumns: ['Timestamp', 'AlertId', 'Title', 'Severity', 'ServiceSource'],
  },
  {
    name: 'AlertEvidence',
    purpose: 'Entities and evidence associated with alerts.',
    keyColumns: ['Timestamp', 'AlertId', 'EntityType', 'EvidenceRole', 'DeviceId'],
  },
  {
    name: 'DeviceInfo',
    purpose: 'Device inventory and operating-system state.',
    keyColumns: ['Timestamp', 'DeviceId', 'DeviceName', 'OSPlatform', 'ExposureLevel'],
  },
  {
    name: 'DeviceEvents',
    purpose: 'Endpoint security-control and miscellaneous device events.',
    keyColumns: ['Timestamp', 'DeviceId', 'ActionType', 'FileName', 'AdditionalFields'],
  },
  {
    name: 'DeviceFileEvents',
    purpose: 'File creation, modification, and deletion events.',
    keyColumns: ['Timestamp', 'DeviceId', 'ActionType', 'FileName', 'SHA256'],
  },
  {
    name: 'DeviceFileCertificateInfo',
    purpose: 'Certificate details observed during file verification.',
    keyColumns: ['Timestamp', 'DeviceId', 'SHA1', 'Signer', 'CertificateSerialNumber'],
  },
  {
    name: 'DeviceImageLoadEvents',
    purpose: 'DLL and executable image-load activity.',
    keyColumns: ['Timestamp', 'DeviceId', 'FileName', 'FolderPath', 'SHA256'],
  },
  {
    name: 'DeviceLogonEvents',
    purpose: 'Interactive, network, and service logons on devices.',
    keyColumns: ['Timestamp', 'DeviceId', 'ActionType', 'AccountName', 'LogonType'],
  },
  {
    name: 'DeviceNetworkEvents',
    purpose: 'Network connections and related endpoint events.',
    keyColumns: ['Timestamp', 'DeviceId', 'ActionType', 'RemoteIP', 'RemoteUrl'],
  },
  {
    name: 'DeviceNetworkInfo',
    purpose: 'Device interfaces, addresses, networks, and domains.',
    keyColumns: ['Timestamp', 'DeviceId', 'NetworkAdapterName', 'IPAddresses', 'MacAddress'],
  },
  {
    name: 'DeviceProcessEvents',
    purpose: 'Process creation and related execution activity.',
    keyColumns: [
      'Timestamp',
      'DeviceId',
      'FileName',
      'ProcessCommandLine',
      'InitiatingProcessFileName',
    ],
  },
  {
    name: 'DeviceRegistryEvents',
    purpose: 'Windows Registry creation and modification events.',
    keyColumns: ['Timestamp', 'DeviceId', 'ActionType', 'RegistryKey', 'RegistryValueData'],
  },
  {
    name: 'DeviceTvmHardwareFirmware',
    purpose: 'Device hardware and firmware inventory.',
    keyColumns: ['DeviceId', 'DeviceName', 'ComponentType', 'Manufacturer', 'ComponentVersion'],
  },
  {
    name: 'DeviceTvmInfoGathering',
    purpose: 'Vulnerability-management assessment events.',
    keyColumns: ['Timestamp', 'DeviceId', 'EventId', 'EventResult', 'AdditionalFields'],
  },
  {
    name: 'DeviceTvmSecureConfigurationAssessment',
    purpose: 'Per-device secure-configuration assessment results.',
    keyColumns: ['DeviceId', 'ConfigurationId', 'IsCompliant', 'IsApplicable', 'Context'],
  },
  {
    name: 'DeviceTvmSoftwareInventory',
    purpose: 'Installed software and end-of-support inventory.',
    keyColumns: [
      'DeviceId',
      'SoftwareVendor',
      'SoftwareName',
      'SoftwareVersion',
      'EndOfSupportStatus',
    ],
  },
  {
    name: 'DeviceTvmSoftwareVulnerabilities',
    purpose: 'Software vulnerabilities affecting devices.',
    keyColumns: [
      'DeviceId',
      'CveId',
      'SoftwareVendor',
      'SoftwareName',
      'VulnerabilitySeverityLevel',
    ],
  },
  {
    name: 'DeviceTvmSoftwareVulnerabilitiesKB',
    purpose: 'Vulnerability knowledge base and exploit metadata.',
    keyColumns: ['CveId', 'CvssScore', 'IsExploitAvailable', 'PublishedDate', 'LastModifiedTime'],
  },
  {
    name: 'EmailEvents',
    purpose: 'Microsoft 365 email delivery and blocking events.',
    keyColumns: [
      'Timestamp',
      'NetworkMessageId',
      'SenderFromAddress',
      'RecipientEmailAddress',
      'DeliveryAction',
    ],
  },
  {
    name: 'EmailAttachmentInfo',
    purpose: 'Files attached to Microsoft 365 messages.',
    keyColumns: ['Timestamp', 'NetworkMessageId', 'FileName', 'FileType', 'SHA256'],
  },
  {
    name: 'EmailPostDeliveryEvents',
    purpose: 'Security actions occurring after email delivery.',
    keyColumns: [
      'Timestamp',
      'NetworkMessageId',
      'ActionType',
      'RecipientEmailAddress',
      'DeliveryLocation',
    ],
  },
  {
    name: 'EmailUrlInfo',
    purpose: 'URLs extracted from Microsoft 365 messages.',
    keyColumns: ['Timestamp', 'NetworkMessageId', 'Url', 'UrlDomain'],
  },
  {
    name: 'UrlClickEvents',
    purpose: 'Safe Links clicks in email, Teams, and Office applications.',
    keyColumns: ['Timestamp', 'AccountUpn', 'Url', 'ActionType', 'ThreatTypes'],
  },
  {
    name: 'IdentityAccountInfo',
    purpose: 'Identity account records from Entra ID and other providers.',
    keyColumns: [
      'Timestamp',
      'AccountObjectId',
      'AccountUpn',
      'SourceProvider',
      'DefenderRiskLevel',
    ],
  },
  {
    name: 'IdentityDirectoryEvents',
    purpose: 'Directory and system events captured from Active Directory.',
    keyColumns: ['Timestamp', 'ActionType', 'AccountUpn', 'TargetAccountUpn', 'DeviceName'],
  },
  {
    name: 'IdentityInfo',
    purpose: 'Unified identity attributes and risk context.',
    keyColumns: ['Timestamp', 'AccountObjectId', 'AccountUPN', 'IdentityEnvironment', 'RiskLevel'],
  },
  {
    name: 'IdentityLogonEvents',
    purpose: 'Authentication events from Active Directory and Microsoft online services.',
    keyColumns: ['Timestamp', 'ActionType', 'AccountUpn', 'Application', 'IPAddress'],
  },
  {
    name: 'IdentityQueryEvents',
    purpose: 'Queries for Active Directory users, groups, devices, and domains.',
    keyColumns: ['Timestamp', 'ActionType', 'QueryType', 'QueryTarget', 'AccountUpn'],
  },
  {
    name: 'EntraIdSignInEvents',
    purpose: 'Microsoft Entra interactive and non-interactive sign-ins.',
    keyColumns: ['Timestamp', 'AccountUpn', 'Application', 'IPAddress', 'ErrorCode'],
  },
  {
    name: 'EntraIdSpnSignInEvents',
    purpose: 'Microsoft Entra service-principal and managed-identity sign-ins.',
    keyColumns: ['Timestamp', 'ServicePrincipalId', 'Application', 'IPAddress', 'ErrorCode'],
  },
  {
    name: 'CloudAppEvents',
    purpose: 'Account and object activity across cloud applications.',
    keyColumns: ['Timestamp', 'ActionType', 'AccountId', 'Application', 'IPAddress'],
  },
  {
    name: 'CloudAuditEvents',
    purpose: 'Audit events from cloud platforms protected by Defender for Cloud.',
    keyColumns: ['Timestamp', 'ActionType', 'CloudPlatform', 'AccountId', 'ResourceId'],
  },
  {
    name: 'ExposureGraphNodes',
    purpose: 'Entities and assets in the Security Exposure Management graph.',
    keyColumns: ['NodeId', 'NodeLabel', 'NodeName', 'NodeProperties', 'EntityIds'],
  },
  {
    name: 'ExposureGraphEdges',
    purpose: 'Relationships between entities in the exposure graph.',
    keyColumns: ['EdgeId', 'EdgeLabel', 'SourceNodeId', 'TargetNodeId', 'EdgeProperties'],
  },
  {
    name: 'OAuthAppInfo',
    purpose: 'OAuth applications available through Cloud Apps app governance.',
    keyColumns: ['Timestamp', 'OAuthAppId', 'AppName', 'Publisher', 'PrivilegeLevel'],
  },
] as const;
