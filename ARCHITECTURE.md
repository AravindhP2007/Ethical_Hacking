# API Vulnerability Scanner - Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Interfaces                              │
├─────────────────────────────────────────────────────────────────┤
│  CLI (cli.py)  │  Python API  │  Quick Start (.vscode/hacking.py)│
└────────┬────────┴──────┬───────┴──────────────┬─────────────────┘
         │               │                      │
         └───────────────┴──────────────────────┘
                         │
                         ▼
         ┌───────────────────────────────┐
         │   VulnerabilityScanner        │
         │   (Main Orchestrator)         │
         └───────────────┬───────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌────────────────────┐         ┌────────────────────┐
│ ConfigurationManager│         │ FalsePositiveDB    │
│ - Load config      │         │ - Load/Save FPs    │
│ - Validate         │         │ - Check FPs        │
└────────┬───────────┘         └────────┬───────────┘
         │                               │
         ▼                               │
┌────────────────────┐                   │
│ EndpointDiscovery  │                   │
│ - OpenAPI parsing  │                   │
│ - Manual config    │                   │
│ - Method probing   │                   │
└────────┬───────────┘                   │
         │                               │
         ▼                               │
┌────────────────────────────────────────┴───────────┐
│           SecurityCheckEngine                      │
│  ┌──────────────────────────────────────────────┐ │
│  │  Security Checks (Pluggable)                 │ │
│  ├──────────────────────────────────────────────┤ │
│  │  1. AuthenticationCheck                      │ │
│  │  2. InjectionCheck                           │ │
│  │  3. AccessControlCheck                       │ │
│  │  4. SensitiveDataCheck                       │ │
│  │  5. RateLimitCheck                           │ │
│  │  6. SecurityMisconfigurationCheck            │ │
│  └──────────────────────────────────────────────┘ │
│  - Execute checks                                  │
│  - Throttle requests                               │
│  - Handle errors                                   │
└────────┬───────────────────────────────────────────┘
         │
         ▼
┌────────────────────┐
│ VulnerabilityAnalyzer│
│ - Analyze results  │
│ - Assign severity  │
│ - Calculate confidence│
│ - Filter FPs       │◄──────────────────────────────┘
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  AlertGenerator    │
│ - Create alerts    │
│ - Add remediation  │
│ - OWASP mapping    │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  ReportExporter    │
│ - Export JSON      │
│ - Export HTML      │
│ - Export PDF       │
└────────────────────┘
```

## Data Flow

```
1. Configuration
   ┌─────────────┐
   │ Config File │
   │  or CLI     │
   └──────┬──────┘
          │
          ▼
   ┌─────────────────┐
   │ ScanConfiguration│
   └──────┬──────────┘
          │
          ▼

2. Discovery Phase
   ┌─────────────┐
   │  Base URL   │
   └──────┬──────┘
          │
          ▼
   ┌─────────────────┐
   │ OpenAPI Spec    │
   │  or Manual      │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ List[Endpoint]  │
   └──────┬──────────┘
          │
          ▼

3. Testing Phase
   ┌─────────────────┐
   │ For each        │
   │ Endpoint        │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ Execute all     │
   │ Security Checks │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ List[CheckResult]│
   └──────┬──────────┘
          │
          ▼

4. Analysis Phase
   ┌─────────────────┐
   │ Analyze Results │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ List[Vulnerability]│
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ Filter FPs      │
   └──────┬──────────┘
          │
          ▼

5. Alert Generation
   ┌─────────────────┐
   │ Generate Alerts │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ Add Remediation │
   └──────┬──────────┘
          │
          ▼
   ┌─────────────────┐
   │ List[Alert]     │
   └──────┬──────────┘
          │
          ▼

6. Reporting Phase
   ┌─────────────────┐
   │  ScanReport     │
   └──────┬──────────┘
          │
          ├──────────┐
          │          │
          ▼          ▼
   ┌──────────┐  ┌──────────┐
   │   JSON   │  │   HTML   │
   └──────────┘  └──────────┘
```

## Component Interactions

```
┌─────────────────────────────────────────────────────────┐
│                  VulnerabilityScanner                    │
│                                                          │
│  scan() {                                                │
│    1. endpoints = discover_endpoints()                   │
│    2. results = execute_security_checks(endpoints)       │
│    3. vulnerabilities = analyze(results)                 │
│    4. alerts = generate_alerts(vulnerabilities)          │
│    5. report = create_report(alerts)                     │
│    6. return report                                      │
│  }                                                       │
└─────────────────────────────────────────────────────────┘
```

## Security Check Flow

```
┌─────────────────────────────────────────────────────────┐
│              SecurityCheck (Abstract Base)               │
│  - check_name() -> str                                   │
│  - execute(endpoint, config) -> CheckResult              │
└─────────────────────────────────────────────────────────┘
                         ▲
                         │ Inherits
         ┌───────────────┴───────────────┐
         │                               │
┌────────┴────────┐            ┌────────┴────────┐
│ Authentication  │            │   Injection     │
│     Check       │            │     Check       │
├─────────────────┤            ├─────────────────┤
│ - Missing auth  │            │ - SQL injection │
│ - Weak schemes  │            │ - NoSQL inject  │
│ - Default creds │            │ - Cmd injection │
└─────────────────┘            │ - XML injection │
                               └─────────────────┘
         │                               │
         └───────────────┬───────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
┌────────┴────────┐            ┌────────┴────────┐
│ Access Control  │            │ Sensitive Data  │
│     Check       │            │     Check       │
├─────────────────┤            ├─────────────────┤
│ - IDOR          │            │ - Exposed creds │
│ - Broken authz  │            │ - Missing HTTPS │
│ - Priv escalate │            │ - Data in errors│
└─────────────────┘            └─────────────────┘
         │                               │
         └───────────────┬───────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
┌────────┴────────┐            ┌────────┴────────┐
│  Rate Limit     │            │ Security        │
│     Check       │            │ Misconfiguration│
├─────────────────┤            ├─────────────────┤
│ - Missing limit │            │ - Verbose errors│
│ - Bad config    │            │ - Missing hdrs  │
└─────────────────┘            │ - Unnecessary   │
                               │   methods       │
                               └─────────────────┘
```

## Data Models

```
ScanConfiguration
├── base_url: str
├── endpoints: List[str]
├── excluded_endpoints: List[str]
├── security_checks: List[str]
├── custom_headers: Dict[str, str]
├── auth_credentials: AuthCredentials
├── severity_threshold: SeverityLevel
├── dry_run: bool
├── read_only: bool
├── request_throttle_ms: int
└── verbose_logging: bool

Endpoint
├── path: str
├── methods: List[HttpMethod]
├── parameters: List[Parameter]
└── authentication_required: bool

CheckResult
├── check_name: str
├── endpoint: str
├── vulnerable: bool
├── evidence: str
└── raw_response: HttpResponse

Vulnerability
├── type: str
├── severity: SeverityLevel
├── confidence: float
├── endpoint: str
├── evidence: str
└── check_result: CheckResult

Alert
├── id: str
├── vulnerability: Vulnerability
├── remediation: RemediationGuidance
├── timestamp: datetime
└── requires_manual_verification: bool

ScanReport
├── scan_id: str
├── timestamp: datetime
├── configuration: ScanConfiguration
├── endpoints_scanned: int
├── checks_performed: int
├── alerts: List[Alert]
└── scan_duration: timedelta
```

## Execution Flow

```
User Input
    │
    ▼
┌─────────────────┐
│ Parse Config    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Validate Config │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Discover        │
│ Endpoints       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ For Each        │
│ Endpoint:       │
│                 │
│ ┌─────────────┐ │
│ │ Auth Check  │ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ Inject Check│ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ Access Check│ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ Data Check  │ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ Rate Check  │ │
│ └─────────────┘ │
│ ┌─────────────┐ │
│ │ Config Check│ │
│ └─────────────┘ │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Analyze Results │
│ - Severity      │
│ - Confidence    │
│ - Filter FPs    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Generate Alerts │
│ - Remediation   │
│ - OWASP Map     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Create Report   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Export Reports  │
│ - JSON          │
│ - HTML          │
│ - PDF           │
└─────────────────┘
```

## Error Handling Strategy

```
┌─────────────────────────────────────────┐
│         Error Handling Layers            │
├─────────────────────────────────────────┤
│                                          │
│  1. Configuration Level                  │
│     - Validate before scan               │
│     - Fail fast on invalid config        │
│                                          │
│  2. Discovery Level                      │
│     - Log errors                         │
│     - Fall back to manual config         │
│     - Continue with valid endpoints      │
│                                          │
│  3. Check Execution Level                │
│     - Try/catch per check                │
│     - Log error                          │
│     - Continue with next check           │
│     - Never terminate scan               │
│                                          │
│  4. Analysis Level                       │
│     - Default values on error            │
│     - Flag for manual review             │
│     - Continue processing                │
│                                          │
│  5. Export Level                         │
│     - Try multiple formats               │
│     - Ensure at least one succeeds       │
│     - Log failures                       │
│                                          │
└─────────────────────────────────────────┘
```

## Extensibility Points

```
1. Add New Security Check
   ┌─────────────────────────────────┐
   │ class MyCheck(SecurityCheck):   │
   │   def check_name(self):         │
   │     return "my_check"            │
   │   def execute(self, ...):       │
   │     # Implementation             │
   └─────────────────────────────────┘

2. Add New Report Format
   ┌─────────────────────────────────┐
   │ class ReportExporter:           │
   │   def export_xml(self, ...):    │
   │     # XML export logic           │
   └─────────────────────────────────┘

3. Custom Vulnerability Analysis
   ┌─────────────────────────────────┐
   │ class VulnerabilityAnalyzer:    │
   │   def custom_analysis(self):    │
   │     # Custom logic               │
   └─────────────────────────────────┘
```

---

This architecture provides:
- **Modularity**: Each component has a single responsibility
- **Extensibility**: Easy to add new checks or features
- **Maintainability**: Clear separation of concerns
- **Testability**: Each component can be tested independently
- **Reliability**: Comprehensive error handling at every level
