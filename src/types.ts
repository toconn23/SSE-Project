//type that contains information from the route analysis
export interface RouteInfo {
  filePath: string;
  method: string[];
  sinks: Sink[];
  hasAuthentication: boolean;
  authorizationChecks: AuthCheck[];
  parameters: Parameter[];
  middleware: string[];
  methodDetails: MethodDetails[];
}

//type that contains method details
export interface MethodDetails {
  method: string;
  sinks: Sink[];
  hasAuthentication: boolean;
  authorizationChecks: AuthCheck[];
}

//type that contains information about the sinks in the route
export interface Sink {
  type:
    | "database_write"
    | "file_write"
    | "session_modify"
    | "user_table_read"
    | "raw_sql"
    | string; //for custom sinks
  location: string;
  callPath: string[];
  isProtected?: boolean; // Whether the sink is protected by auth conditionals
  customSeverity?: "critical" | "high" | "medium" | "low"; //for custom sinks
}

//type for security config
export interface SecurityConfig {
  customRoles?: string[];
  sessionTokens?: {
    user?: string;
    admin?: string;
  };
  customSinks?: CustomSinkDefinition[];
}

//type for custom sink definitions
export interface CustomSinkDefinition {
  name: string;
  patterns: string[];
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

//type that contains information about the authorization checks in the route
export interface AuthCheck {
  type: "session_check" | "role_check" | "ownership_check";
  location: string;
  details: string;
}

//type that contains information about the parameters in the route
export interface Parameter {
  name: string;
  source: "body" | "query" | "params";
  containsObjectId: boolean;
}

//type that contains information about the analysis report
export interface AnalysisReport {
  totalRoutes: number;
  routesWithSinks: number;
  routesWithoutAuth: number;
  vulnerableRoutes: VulnerableRoute[];
  routes: RouteInfo[]; //for debug purposes, will not print in report later
}

//type that contains information about the vulnerable routes
export interface VulnerableRoute {
  route: string;
  methods: string[];
  vulnerability: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

//type that contains information about fuzzing results
export interface FuzzResult {
  route: string;
  method: string;
  vulnerability: string;
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: any;
  };
  response: {
    status: number;
    body?: any;
  };
  exploitable: boolean;
  description: string;
}

//type that contains information about the fuzzing report
export interface FuzzReport {
  timestamp: string;
  totalTests: number;
  vulnerabilitiesConfirmed: number;
  vulnerabilitiesRejected: number;
  results: FuzzResult[];
}

//type for generic endpoint test result (reusable for different vulnerability types)
export interface EndpointTestResult {
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: any;
  };
  response: {
    status: number;
    body?: any;
  };
  error?: string;
}

//type for final combined report
export interface FinalReport {
  timestamp: string;
  summary: {
    totalRoutes: number;
    totalVulnerabilities: number;
    confirmedVulnerabilities: number;
    unconfirmedVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  findings: Finding[];
}

//type for individual finding in final report
export interface Finding {
  id: number;
  route: string;
  method: string;
  vulnerability: string;
  severity: "critical" | "high" | "medium" | "low";
  confirmed: boolean;
  description: string;
  fix: string;
}
