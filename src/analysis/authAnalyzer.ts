import { Node, SourceFile } from "ts-morph";
import { AuthCheck, SecurityConfig } from "../types";

export class AuthAnalyzer {
  private config: SecurityConfig;

  constructor(config: SecurityConfig = {}) {
    this.config = config;
  }

  hasAuthPatternInNode(node: Node): boolean {
    const text = node.getText().toLowerCase();

    const authPatterns = [
      "session",
      "authenticated",
      "auth()",
      "getserversession",
      "usesession",
      "getsession",
      "nextauth",
      "next-auth",
      "user",
      "token",
    ];

    //check for role patterns
    const rolePatterns = ["role", "admin", "permission"];
    const customRoles = (this.config.customRoles || []).map((r) =>
      r.toLowerCase()
    );
    const hasAuthPattern = authPatterns.some((pattern) =>
      text.includes(pattern)
    );
    const hasRolePattern = rolePatterns.some((pattern) =>
      text.includes(pattern)
    );
    const hasCustomRole = customRoles.some((role) => text.includes(role));
    return hasAuthPattern || hasRolePattern || hasCustomRole;
  }

  extractAuthChecks(node: Node): AuthCheck[] {
    const checks: AuthCheck[] = [];

    node.forEachDescendant((descendant) => {
      const nodeText = descendant.getText();
      const line = descendant.getStartLineNumber();

      //Session checks
      if (nodeText.includes("session") && nodeText.length < 200) {
        checks.push({
          type: "session_check",
          location: `Line ${line}`,
          details: nodeText.substring(0, 100),
        });
      }

      const defaultRoleKeywords = ["role", "admin"];
      const hasDefaultRoleCheck = defaultRoleKeywords.some((keyword) =>
        nodeText.includes(keyword)
      );

      //check for custom roles from config
      const customRoles = this.config.customRoles || [];
      const hasCustomRoleCheck = customRoles.some((role) =>
        nodeText.includes(role)
      );

      if (
        (hasDefaultRoleCheck || hasCustomRoleCheck) &&
        nodeText.length < 200
      ) {
        //make sure the check makes sense
        if (
          nodeText.includes("===") ||
          nodeText.includes("==") ||
          nodeText.includes("!==") ||
          nodeText.includes("!=") ||
          nodeText.includes("if")
        ) {
          checks.push({
            type: "role_check",
            location: `Line ${line}`,
            details: nodeText.substring(0, 100),
          });
        }
      }

      //ownership checks
      if (
        nodeText.includes("userId") &&
        (nodeText.includes("===") || nodeText.includes("==")) &&
        nodeText.length < 200
      ) {
        checks.push({
          type: "ownership_check",
          location: `Line ${line}`,
          details: nodeText.substring(0, 100),
        });
      }
    });
    //remove duplicates based on location
    const uniqueChecks = checks.filter(
      (check, index, self) =>
        index === self.findIndex((c) => c.location === check.location)
    );

    return uniqueChecks;
  }

  detectMiddleware(sourceFile: SourceFile): string[] {
    const middleware: string[] = [];

    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();
        let callName = "";

        if (Node.isIdentifier(expression)) {
          callName = expression.getText();
        } else if (Node.isPropertyAccessExpression(expression)) {
          callName = expression.getText();
        }

        if (
          callName.includes("middleware") ||
          callName.includes("withAuth") ||
          callName.includes("requireAuth")
        ) {
          middleware.push(callName);
        }
      }
    });

    return [...new Set(middleware)];
  }

  hasAuthMiddleware(middleware: string[]): boolean {
    if (!middleware || middleware.length === 0) return false;
    const patterns = ["withauth", "requireauth", "auth"];
    return middleware.some((mw) => {
      const lower = mw.toLowerCase();
      return patterns.some((p) => lower.includes(p));
    });
  }
}
