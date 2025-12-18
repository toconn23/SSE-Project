import { AnalysisReport, FuzzResult, FuzzReport } from "../types";
import { fuzzEndpoint, generateFuzzCases, getRoutePath } from "./fuzzUtils";

/**
 * Fuzzes routes that have mutation endpoints without authentication
 */
export async function fuzzMissingAuthentication(
  report: AnalysisReport,
  baseUrl: string
): Promise<FuzzReport> {
  const results: FuzzResult[] = [];
  let totalTests = 0;

  // Find vulnerable routes - mutation endpoints without authentication
  for (const route of report.routes) {
    for (const methodDetail of route.methodDetails) {
      //check if it's a mutation method without authentication and has sinks or if its any method without authentication that has sensitive custom sinks
      const hasSensitiveSink = methodDetail.sinks.some(
        (sink) =>
          sink.type === "database_write" ||
          sink.type === "session_modify" ||
          sink.type === "file_write" ||
          (sink.customSeverity &&
            (sink.customSeverity === "high" ||
              sink.customSeverity === "critical" ||
              sink.customSeverity === "medium"))
      );

      if (
        !methodDetail.hasAuthentication &&
        methodDetail.sinks.length > 0 &&
        hasSensitiveSink
      ) {
        const routePath = getRoutePath(route.filePath);
        console.log(
          `\nFuzzing ${methodDetail.method} ${routePath} - Missing Authentication`
        );

        // Generate fuzz cases and test endpoint
        const fuzzCases = generateFuzzCases(route, methodDetail);

        for (const fuzzCase of fuzzCases) {
          const testResult = await fuzzEndpoint(
            baseUrl,
            routePath,
            methodDetail.method,
            fuzzCase
          );

          // Check if missing authentication vulnerability is exploitable
          const exploitable =
            testResult.response.status >= 200 &&
            testResult.response.status < 300;

          const fuzzResult: FuzzResult = {
            route: routePath,
            method: methodDetail.method,
            vulnerability: "missing_authentication",
            request: testResult.request,
            response: testResult.response,
            exploitable,
            description: exploitable
              ? `Successfully accessed ${methodDetail.method} ${routePath} without authentication. Response: ${testResult.response.status}`
              : `Request to ${methodDetail.method} ${routePath} was rejected with status ${testResult.response.status}`,
          };

          results.push(fuzzResult);
          totalTests++;

          if (exploitable) {
            console.log(
              `VULN CONFIRMED: ${methodDetail.method} ${routePath} (Status: ${testResult.response.status})`
            );
            // Stop testing this route once vulnerability is confirmed
            break;
          } else {
            console.log(
              `Protected: ${methodDetail.method} ${routePath} (Status: ${testResult.response.status})`
            );
          }
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

/**
 * Checks if a method is a mutation method (POST or PUT only)
 */
function isMutationMethod(method: string): boolean {
  return ["POST", "PUT", "DELETE"].includes(method.toUpperCase());
}
