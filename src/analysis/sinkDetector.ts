import { Node, CallExpression } from "ts-morph";
import { Sink, SecurityConfig } from "../types";
import { ASTUtils } from "./astUtils";

export class SinkDetector {
  private astUtils: ASTUtils;
  private config: SecurityConfig;

  constructor(astUtils: ASTUtils, config: SecurityConfig = {}) {
    this.astUtils = astUtils;
    this.config = config;
  }

  detectSinks(node: Node): Sink[] {
    const sinks: Sink[] = [];
    const dbWritePatterns = [
      "create",
      "update",
      "delete",
      "insert",
      "save",
      "remove",
      "upsert",
      "deleteMany",
      "updateMany",
    ];
    const dbReadPatterns = ["findMany", "findUnique", "findFirst", "query"];
    const fileWritePatterns = [
      "writeFile",
      "writeFileSync",
      "appendFile",
      "unlink",
      "unlinkSync",
      "rmSync",
      "rm",
    ];
    const rawSqlPatterns = [
      "$queryRaw",
      "$executeRaw",
      "queryRaw",
      "executeRaw",
      "raw",
    ];

    node.forEachDescendant((descendant) => {
      if (Node.isCallExpression(descendant)) {
        const calleeText = this.astUtils.getCallExpressionName(descendant);
        const line = descendant.getStartLineNumber();

        if (rawSqlPatterns.some((pattern) => calleeText.includes(pattern))) {
          const code = descendant.getText();
          const upperCode = code.toUpperCase();
          const hasDangerousSQL =
            upperCode.includes("DELETE") ||
            upperCode.includes("UPDATE") ||
            upperCode.includes("INSERT") ||
            upperCode.includes("DROP") ||
            upperCode.includes("ALTER") ||
            upperCode.includes("TRUNCATE");

          //check if SQL reads from user table
          const isUserTableRead =
            upperCode.includes("SELECT") &&
            (code.includes("user") || code.includes("User"));

          if (hasDangerousSQL) {
            sinks.push({
              type: "raw_sql",
              location: `Line ${line}`,
              callPath: [calleeText],
            });
          } else if (isUserTableRead) {
            sinks.push({
              type: "user_table_read",
              location: `Line ${line}`,
              callPath: [calleeText],
            });
          }
        }

        if (dbWritePatterns.some((pattern) => calleeText.includes(pattern))) {
          sinks.push({
            type: "database_write",
            location: `Line ${line}`,
            callPath: [calleeText],
          });
        }

        if (dbReadPatterns.some((pattern) => calleeText.includes(pattern))) {
          const code = descendant.getText();
          if (code.includes("user") || code.includes("User")) {
            sinks.push({
              type: "user_table_read",
              location: `Line ${line}`,
              callPath: [calleeText],
            });
          }
        }

        if (fileWritePatterns.some((pattern) => calleeText.includes(pattern))) {
          sinks.push({
            type: "file_write",
            location: `Line ${line}`,
            callPath: [calleeText],
          });
        }
        //see if modifies session
        if (
          calleeText.includes("session") &&
          (calleeText.includes("set") || calleeText.includes("update"))
        ) {
          sinks.push({
            type: "session_modify",
            location: `Line ${line}`,
            callPath: [calleeText],
          });
        }

        //check custom sinks
        if (this.config.customSinks) {
          for (const customSink of this.config.customSinks) {
            if (
              customSink.patterns.some((pattern) =>
                calleeText.includes(pattern)
              )
            ) {
              sinks.push({
                type: customSink.name,
                location: `Line ${line}`,
                callPath: [calleeText],
                customSeverity: customSink.severity,
              });
            }
          }
        }
      }
    });

    return sinks;
  }
}
