#!/usr/bin/env node
import { RouteDiscovery } from "./routeDiscovery";
import { Analyzer } from "./analyzer";
import { Reporter } from "./reporter";
import { Fuzzer } from "./fuzzer";
import { RouteInfo, SecurityConfig } from "./types";
import * as path from "path";
import * as fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  if (!args[0]) {
    console.error(
      "Usage: ts-node src/index.ts <target-directory> [--fuzz] [--base-url <url>]"
    );
    console.error(
      "Example: ts-node src/index.ts data/vuln-app --fuzz --base-url http://localhost:3000"
    );
    process.exit(1);
  }

  const targetDir = args[0];
  const shouldFuzz = args.includes("--fuzz");
  const baseUrlIndex = args.indexOf("--base-url");
  const baseUrl =
    baseUrlIndex !== -1 ? args[baseUrlIndex + 1] : "http://localhost:3000";

  console.log(`Analyzing: ${targetDir}\n`);

  try {
    //Load optional security config if exists
    let config: SecurityConfig = {};
    const configPath = path.join(targetDir, "security-config.json");
    if (fs.existsSync(configPath)) {
      console.log("Loading security config...");
      const configContent = fs.readFileSync(configPath, "utf-8");
      config = JSON.parse(configContent);
      console.log(
        `Loaded custom roles: ${config.customRoles?.join(", ") || "none"}\n`
      );
    }

    //find API routes
    console.log("Discovering API routes...");
    const discovery = new RouteDiscovery(targetDir);
    const routeFiles = await discovery.discoverRoutes();
    console.log(`Found ${routeFiles.length} API route files\n`);

    if (routeFiles.length === 0) {
      console.log("No Next.js API routes found in the target directory.");
      return;
    }

    console.log("Analyzing routes for security issues...");
    const analyzer = new Analyzer(config);
    const routes: RouteInfo[] = [];

    //for all route file, read the content, analyze, and add to array
    for (const routeFile of routeFiles) {
      try {
        const content = discovery.readRouteFile(routeFile);
        const routeInfo = analyzer.analyzeRoute(routeFile, content);
        routes.push(routeInfo);
        console.log(`Analyzed: ${path.relative(targetDir, routeFile)}`);
      } catch (error) {
        console.error(
          `Error analyzing ${routeFile}:`,
          (error as Error).message
        );
      }
    }

    console.log(`\nAnalyzed ${routes.length} routes successfully\n`);

    //generate static analysis report
    const reporter = new Reporter();
    const analysisReport = reporter.generateReport(routes);

    //save static analysis report
    const securityReportPath = path.join(targetDir, "security-report.json");
    fs.writeFileSync(
      securityReportPath,
      JSON.stringify(analysisReport, null, 2)
    );
    console.log(`Security report saved to: ${securityReportPath}`);

    //run fuzzing if requested
    let fuzzingReport;
    if (shouldFuzz) {
      console.log("Running fuzzer...");
      const fuzzer = new Fuzzer(baseUrl, config);

      const missingAuthReport = await fuzzer.fuzzMissingAuthentication(
        analysisReport
      );
      const privEscReport = await fuzzer.fuzzPrivilegeEscalation(
        analysisReport
      );

      fuzzingReport = reporter.generateFuzzingReport(
        missingAuthReport,
        privEscReport
      );

      //save fuzzing report
      const fuzzingReportPath = path.join(targetDir, "fuzzing-report.json");
      fs.writeFileSync(
        fuzzingReportPath,
        JSON.stringify(fuzzingReport, null, 2)
      );
      console.log(`Fuzzing report saved to: ${fuzzingReportPath}`);
    }

    //generate and display final report
    const finalReport = reporter.generateFinalReport(
      analysisReport,
      fuzzingReport
    );
    reporter.printFinalReport(finalReport);

    //save final report
    const finalOutputPath = path.join(targetDir, "final-report.json");
    reporter.saveFinalReport(finalReport, finalOutputPath);
    console.log(`Final report saved to: ${finalOutputPath}`);
  } catch (error) {
    console.error("Analysis failed:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("error:", error);
  process.exit(1);
});
