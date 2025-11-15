import { glob } from "glob";
import * as path from "path";
import * as fs from "fs";

export class RouteDiscovery {
  private targetDir: string;

  constructor(targetDir: string) {
    this.targetDir = targetDir;
  }

  /**
   * Discovers all Next.js API route files
   * Supports both app router (app/api/**) and pages router (pages/api/**)
   */
  async discoverRoutes(): Promise<string[]> {
    //files following these patterns should contain API routes
    const patterns = [
      "app/api/**/*.ts",
      "app/api/**/*.tsx",
      "pages/api/**/*.ts",
      "pages/api/**/*.tsx",
    ];

    const routes: string[] = [];

    for (const pattern of patterns) {
      //Use forward slashes for glob pattern and normalize the path
      const fullPattern = path
        .join(this.targetDir, pattern)
        .replace(/\\/g, "/"); //thanks Windows
      const files = await glob(fullPattern, {
        ignore: ["**/node_modules/**", "**/dist/**", "**/.next/**"],
        windowsPathsNoEscape: true,
      });
      routes.push(...files);
    }

    //Filter out non-existent files and ensure they're TypeScript
    return routes.filter((route) => {
      if (!fs.existsSync(route)) {
        return false;
      }
      const ext = path.extname(route);
      return ext === ".ts" || ext === ".tsx";
    });
  }

  /**
   * Returns the content of a route file
   */
  readRouteFile(filePath: string): string {
    return fs.readFileSync(filePath, "utf-8");
  }
}
