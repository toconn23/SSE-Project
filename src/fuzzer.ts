import { AnalysisReport, FuzzReport, SecurityConfig } from "./types";
import { fuzzMissingAuthentication } from "./fuzzing/missingAuthentication";
import { fuzzPrivilegeEscalation } from "./fuzzing/privilegeEscalation";

export class Fuzzer {
  private baseUrl: string;
  private config: SecurityConfig;

  constructor(
    baseUrl: string = "http://localhost:3000",
    config: SecurityConfig = {}
  ) {
    this.baseUrl = baseUrl;
    this.config = config;
  }

  //Fuzzes routes that have mutation endpoints without authentication
  async fuzzMissingAuthentication(report: AnalysisReport): Promise<FuzzReport> {
    return fuzzMissingAuthentication(report, this.baseUrl);
  }

  //Fuzzes routes where non-admin users can access admin-only data
  async fuzzPrivilegeEscalation(report: AnalysisReport): Promise<FuzzReport> {
    return fuzzPrivilegeEscalation(report, this.config, this.baseUrl);
  }
}
