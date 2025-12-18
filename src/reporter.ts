import {
  RouteInfo,
  AnalysisReport,
  VulnerableRoute,
  FuzzReport,
  FinalReport,
  Finding,
} from "./types";
import * as fs from "fs";
import * as path from "path";

export class Reporter {
  generateReport(routes: RouteInfo[]): AnalysisReport {
    const vulnerableRoutes = this.identifyVulnerabilities(routes);

    //count route methods with sinks and without authentication
    let routesWithSinks = 0;
    let routesWithoutAuth = 0;

    for (const route of routes) {
      for (const method of route.methodDetails) {
        if (method.sinks.length > 0) {
          routesWithSinks++;
          if (!method.hasAuthentication) {
            routesWithoutAuth++;
          }
        }
      }
    }

    return {
      totalRoutes: routes.length,
      routesWithSinks,
      routesWithoutAuth,
      vulnerableRoutes,
      routes,
    };
  }

  private identifyVulnerabilities(routes: RouteInfo[]): VulnerableRoute[] {
    const vulnerable: VulnerableRoute[] = [];

    for (const route of routes) {
      for (const methodDetail of route.methodDetails) {
        const hasDbWrite = methodDetail.sinks.some(
          (s) => s.type === "database_write"
        );
        const hasRawSql = methodDetail.sinks.some((s) => s.type === "raw_sql");

        //High severity: Raw SQL without authentication
        if (hasRawSql && !methodDetail.hasAuthentication) {
          vulnerable.push({
            route: route.filePath,
            methods: [methodDetail.method],
            vulnerability: "Unsafe Raw SQL Execution",
            severity: "high",
            description: `${methodDetail.method} handler executes raw SQL with dangerous commands without authentication checks`,
          });
        }

        //High severity: Database writes without authentication
        if (hasDbWrite && !methodDetail.hasAuthentication) {
          vulnerable.push({
            route: route.filePath,
            methods: [methodDetail.method],
            vulnerability: "Missing Authentication",
            severity: "high",
            description: `${methodDetail.method} handler performs database writes without authentication checks`,
          });
        }

        //High severity: user table reads without authorization
        const hasUserRead = methodDetail.sinks.some(
          (s) => s.type === "user_table_read"
        );
        const hasRoleCheck = methodDetail.authorizationChecks.some(
          (c) => c.type === "role_check"
        );
        if (hasUserRead && !hasRoleCheck) {
          vulnerable.push({
            route: route.filePath,
            methods: [methodDetail.method],
            vulnerability: "Missing Role Check",
            severity: "high",
            description: `${methodDetail.method} handler reads user table without role-based authorization`,
          });
        }

        //Medium severity: file writes without authentication
        const hasFileWrite = methodDetail.sinks.some(
          (s) => s.type === "file_write"
        );
        if (hasFileWrite && !methodDetail.hasAuthentication) {
          vulnerable.push({
            route: route.filePath,
            methods: [methodDetail.method],
            vulnerability: "Insecure File Operation",
            severity: "medium",
            description: `${methodDetail.method} handler performs file writes without authentication`,
          });
        }

        //check custom sinks
        const customSinks = methodDetail.sinks.filter(
          (s) => s.customSeverity !== undefined
        );
        for (const customSink of customSinks) {
          if (!methodDetail.hasAuthentication) {
            vulnerable.push({
              route: route.filePath,
              methods: [methodDetail.method],
              vulnerability: `Insecure ${customSink.type}`,
              severity: customSink.customSeverity!,
              description: `${methodDetail.method} handler uses ${customSink.type} without authentication checks`,
            });
          } else if (
            customSink.customSeverity === "high" ||
            customSink.customSeverity === "critical"
          ) {
            //for high/critical severity sinks, check for authorization even if protected by auth
            const hasOwnershipCheck = methodDetail.authorizationChecks.some(
              (c) => c.type === "ownership_check"
            );
            const hasRoleCheck = methodDetail.authorizationChecks.some(
              (c) => c.type === "role_check"
            );

            if (!hasOwnershipCheck && !hasRoleCheck) {
              vulnerable.push({
                route: route.filePath,
                methods: [methodDetail.method],
                vulnerability: `Missing Authorization for ${customSink.type}`,
                severity: customSink.customSeverity!,
                description: `${methodDetail.method} handler uses ${customSink.type} with authentication but without proper authorization checks (role or ownership validation)`,
              });
            }
          }
        }
      }
    }

    return vulnerable;
  }

  printReport(report: AnalysisReport): void {
    console.log("\nSecurity Analysis Report");
    console.log("Summary:");
    console.log(`Total Route Files: ${report.totalRoutes}`);
    console.log(`HTTP Methods with Sinks: ${report.routesWithSinks}`);
    console.log(`HTTP Methods without Auth: ${report.routesWithoutAuth}`);
    console.log(`Vulnerable HTTP Methods: ${report.vulnerableRoutes.length}\n`);

    if (report.vulnerableRoutes.length > 0) {
      console.log("Vulnerabilities Found:");

      const highSev = report.vulnerableRoutes.filter(
        (v) => v.severity === "high"
      );
      const medSev = report.vulnerableRoutes.filter(
        (v) => v.severity === "medium"
      );
      const lowSev = report.vulnerableRoutes.filter(
        (v) => v.severity === "low"
      );

      if (highSev.length > 0) {
        console.log("\nHIGH SEVERITY:");
        highSev.forEach((v) => this.printVulnerability(v));
      }

      if (medSev.length > 0) {
        console.log("\nMEDIUM SEVERITY:");
        medSev.forEach((v) => this.printVulnerability(v));
      }

      if (lowSev.length > 0) {
        console.log("\nLOW SEVERITY:");
        lowSev.forEach((v) => this.printVulnerability(v));
      }
    } else {
      console.log("No vulnerabilities detected!");
    }

    console.log("\n");
  }

  private printVulnerability(vuln: VulnerableRoute): void {
    console.log(`\nRoute: ${vuln.route}`);
    console.log(`Methods: ${vuln.methods.join(", ")}`);
    console.log(`Issue: ${vuln.vulnerability}`);
    console.log(`Description: ${vuln.description}`);
  }

  saveReportToFile(report: AnalysisReport, outputPath: string): void {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.log(`\nFull report saved to: ${outputPath}`);
  }

  generateFuzzingReport(...reports: FuzzReport[]): FuzzReport {
    return {
      timestamp: new Date().toISOString(),
      totalTests: reports.reduce((sum, r) => sum + r.totalTests, 0),
      vulnerabilitiesConfirmed: reports.reduce(
        (sum, r) => sum + r.vulnerabilitiesConfirmed,
        0
      ),
      vulnerabilitiesRejected: reports.reduce(
        (sum, r) => sum + r.vulnerabilitiesRejected,
        0
      ),
      results: reports.flatMap((r) => r.results),
    };
  }

  saveFuzzingReport(report: FuzzReport, outputPath: string): void {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  }

  generateFinalReport(
    analysisReport: AnalysisReport,
    fuzzReport?: FuzzReport
  ): FinalReport {
    const findings: Finding[] = [];
    let id = 1;

    for (const vuln of analysisReport.vulnerableRoutes) {
      for (const method of vuln.methods) {
        const fuzzMatch = fuzzReport?.results.find(
          (r) =>
            r.route === vuln.route &&
            r.method === method &&
            r.vulnerability === vuln.vulnerability
        );

        const confirmed = fuzzMatch?.exploitable ?? false;
        const severity = this.calculateSeverity(vuln.severity, confirmed);

        findings.push({
          id: id++,
          route: vuln.route,
          method,
          vulnerability: vuln.vulnerability,
          severity,
          confirmed,
          description: confirmed
            ? `${vuln.description}. Exploitation confirmed via fuzzing.`
            : vuln.description,
          fix: this.getFix(vuln.vulnerability),
        });
      }
    }

    //add any fuzzing-only findings not in static analysis
    if (fuzzReport) {
      for (const result of fuzzReport.results) {
        if (!result.exploitable) continue;

        const alreadyAdded = findings.some(
          (f) =>
            f.route === result.route &&
            f.method === result.method &&
            f.vulnerability === result.vulnerability
        );

        if (!alreadyAdded) {
          findings.push({
            id: id++,
            route: result.route,
            method: result.method,
            vulnerability: result.vulnerability,
            severity: "high",
            confirmed: true,
            description: result.description,
            fix: this.getFix(result.vulnerability),
          });
        }
      }
    }

    //sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort(
      (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
    );

    return {
      timestamp: new Date().toISOString(),
      summary: {
        totalRoutes: analysisReport.totalRoutes,
        totalVulnerabilities: findings.length,
        confirmedVulnerabilities: findings.filter((f) => f.confirmed).length,
        unconfirmedVulnerabilities: findings.filter((f) => !f.confirmed).length,
        criticalCount: findings.filter((f) => f.severity === "critical").length,
        highCount: findings.filter((f) => f.severity === "high").length,
        mediumCount: findings.filter((f) => f.severity === "medium").length,
        lowCount: findings.filter((f) => f.severity === "low").length,
      },
      findings,
    };
  }

  private calculateSeverity(
    baseSeverity: "critical" | "high" | "medium" | "low",
    confirmed: boolean
  ): "critical" | "high" | "medium" | "low" {
    if (baseSeverity === "critical") return "critical";
    if (confirmed && baseSeverity === "high") return "critical";
    if (confirmed) return baseSeverity === "medium" ? "high" : "medium";
    return baseSeverity;
  }

  private getFix(vulnerability: string): string {
    const fixes: Record<string, string> = {
      "Missing Authentication":
        "Add authentication check to verify user identity before processing requests.",
      "Missing Role Check":
        "Implement role-based access control and verify user roles before allowing access to sensitive data or operations.",
      "Unsafe Raw SQL Execution":
        "Make sure the raw SQL is protected by correct authentication and authorization checks.",
      "Insecure File Operation":
        "Make sure the file operation is protected by correct authentication and authorization checks.",
      "Privilege Escalation":
        "Do not allow non-admin users to access admin-only data.",
    };

    return (
      fixes[vulnerability] ||
      "Review the endpoint and implement appropriate security controls."
    );
  }

  printFinalReport(report: FinalReport): void {
    console.log("SECURITY ASSESSMENT REPORT:");
    console.log(`Generated: ${report.timestamp}`);
    console.log("\nSUMMARY:");
    console.log(`Routes Analyzed: ${report.summary.totalRoutes}`);
    console.log(`Total Findings: ${report.summary.totalVulnerabilities}`);
    console.log(`Confirmed: ${report.summary.confirmedVulnerabilities}`);
    console.log(`Unconfirmed: ${report.summary.unconfirmedVulnerabilities}`);
    console.log("\nBY SEVERITY:");
    if (report.summary.criticalCount > 0)
      console.log(`Critical: ${report.summary.criticalCount}`);
    if (report.summary.highCount > 0)
      console.log(`High: ${report.summary.highCount}`);
    if (report.summary.mediumCount > 0)
      console.log(`Medium: ${report.summary.mediumCount}`);
    if (report.summary.lowCount > 0)
      console.log(`Low: ${report.summary.lowCount}`);

    if (report.findings.length > 0) {
      console.log("FINDINGS:");

      for (const finding of report.findings) {
        const status = finding.confirmed ? "CONFIRMED" : "UNCONFIRMED";
        console.log(
          `\n[${finding.severity.toUpperCase()}] #${finding.id}: ${
            finding.vulnerability
          }`
        );
        console.log(`Route: ${finding.route}`);
        console.log(`Method: ${finding.method}`);
        console.log(`Status: ${status}`);
        console.log(`Description: ${finding.description}`);
        console.log(`Fix: ${finding.fix}`);
      }
    } else {
      console.log("\nNo vulnerabilities found.");
    }
  }

  saveFinalReport(report: FinalReport, outputPath: string): void {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  }
}
