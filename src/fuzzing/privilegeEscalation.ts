import {
  AnalysisReport,
  FuzzResult,
  FuzzReport,
  SecurityConfig,
} from "../types";
import { containsUserData, fuzzEndpoint, getRoutePath } from "./fuzzUtils";

export async function fuzzPrivilegeEscalation(
  report: AnalysisReport,
  config: SecurityConfig,
  baseUrl: string
): Promise<FuzzReport> {
  const results: FuzzResult[] = [];
  let totalTests = 0;

  const userToken = config.sessionTokens?.user;
  if (!userToken) {
    console.log(
      "No user session token configured. Skipping privilege escalation testing."
    );
    return {
      timestamp: new Date().toISOString(),
      totalTests: 0,
      vulnerabilitiesConfirmed: 0,
      vulnerabilitiesRejected: 0,
      results: [],
    };
  }

  //Find routes that read from user table or have high/critical custom sinks requiring authorization
  for (const route of report.routes) {
    for (const methodDetail of route.methodDetails) {
      //Check if route reads from user table or has high/critical sinks
      const hasUserTableRead = methodDetail.sinks.some(
        (sink) => sink.type === "user_table_read"
      );

      const hasAuthorizationSensitiveSink = methodDetail.sinks.some(
        (sink) =>
          sink.customSeverity &&
          (sink.customSeverity === "high" || sink.customSeverity === "critical")
      );

      if (hasUserTableRead || hasAuthorizationSensitiveSink) {
        const routePath = getRoutePath(route.filePath);
        console.log(
          `\nFuzzing ${methodDetail.method} ${routePath} - Privilege Escalation (Non-admin accessing user data)`
        );

        // Generate request with non-admin session
        const fuzzCase = {
          headers: {
            "Content-Type": "application/json",
            Cookie: `sessionToken=${userToken}`,
          },
          body: undefined,
        };

        const testResult = await fuzzEndpoint(
          baseUrl,
          routePath,
          methodDetail.method,
          fuzzCase
        );

        //Check if non-admin can access user data
        const isSuccessStatus =
          testResult.response.status >= 200 && testResult.response.status < 300;
        const hasUserData = containsUserData(testResult.response.body);
        const exploitable = isSuccessStatus && hasUserData;

        const fuzzResult: FuzzResult = {
          route: routePath,
          method: methodDetail.method,
          vulnerability: "privilege_escalation",
          request: testResult.request,
          response: testResult.response,
          exploitable,
          description: exploitable
            ? `Non-admin user successfully accessed user table at ${methodDetail.method} ${routePath}. Sensitive user data exposed in response.`
            : !isSuccessStatus
            ? `Non-admin user was denied access to user table at ${methodDetail.method} ${routePath}. Status: ${testResult.response.status}`
            : `Request succeeded but no sensitive user data found in response at ${methodDetail.method} ${routePath}. Status: ${testResult.response.status}`,
        };

        results.push(fuzzResult);
        totalTests++;

        if (exploitable) {
          console.log(
            `VULNERABILITY CONFIRMED: Non-admin accessed ${methodDetail.method} ${routePath} (Status: ${testResult.response.status})`
          );
          console.log(
            `  User data exposed: ${JSON.stringify(testResult.response.body)}`
          );
        } else {
          console.log(
            `Protected: Non-admin denied at ${methodDetail.method} ${routePath} (Status: ${testResult.response.status})`
          );
        }
      }
    }
  }

  const vulnerabilitiesConfirmed = results.filter((r) => r.exploitable).length;
  const vulnerabilitiesRejected = results.filter((r) => !r.exploitable).length;

  return {
    timestamp: new Date().toISOString(),
    totalTests,
    vulnerabilitiesConfirmed,
    vulnerabilitiesRejected,
    results,
  };
}
