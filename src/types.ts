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
    | "database_read"
    | "file_write"
    | "session_modify"
    | "user_table_read"
    | "raw_sql";
  location: string;
  callPath: string[];
  isProtected?: boolean; // Whether the sink is protected by auth conditionals
}

//type for security config
export interface SecurityConfig {
  customRoles?: string[];
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
  source: "body" | "query" | "params" | "cookie";
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
  severity: "high" | "medium" | "low";
  description: string;
}
