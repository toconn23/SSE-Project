import { RouteInfo, AnalysisReport, VulnerableRoute } from "./types";
import * as fs from "fs";
import * as path from "path";

export class Reporter {
  generateReport(routes: RouteInfo[]): AnalysisReport {
    const vulnerableRoutes = this.identifyVulnerabilities(routes);

    // Count methods with sinks (not just routes with sinks)
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
}
