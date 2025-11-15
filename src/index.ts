#!/usr/bin/env node
import { RouteDiscovery } from "./routeDiscovery";
import { Analyzer } from "./analyzer";
import { Reporter } from "./reporter";
import { RouteInfo, SecurityConfig } from "./types";
import * as path from "path";
import * as fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  if (!args[0]) {
    console.error("Provide a target directory");
    process.exit(1);
  }
  const targetDir = args[0];

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

    //TODO: Targeted Fuzzing and change severity based on result
    console.log("TODO: Targeted Fuzzing...");

    //generate and display report
    console.log("Generating security report...");
    const reporter = new Reporter();
    const report = reporter.generateReport(routes);

    reporter.printReport(report);

    //create report
    const outputPath = path.join(targetDir, "security-report.json");
    reporter.saveReportToFile(report, outputPath);

    console.log("\nAnalysis complete");
  } catch (error) {
    console.error("Analysis failed:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("error:", error);
  process.exit(1);
});
