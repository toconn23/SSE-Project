import { Node, SourceFile } from "ts-morph";
import { Parameter } from "../types";
import { ASTUtils } from "./astUtils";

export class ParameterExtractor {
  private astUtils: ASTUtils;

  constructor(astUtils: ASTUtils) {
    this.astUtils = astUtils;
  }

  //get parameters from source file
  extractParameters(sourceFile: SourceFile): Parameter[] {
    const parameters: Parameter[] = [];
    const seen = new Set<string>();

    sourceFile.forEachDescendant((node) => {
      //Look for property access expressions like request.body
      if (Node.isPropertyAccessExpression(node)) {
        const props = this.astUtils.getPropertyAccessChain(node);
        const key = props.join(".");

        if (seen.has(key)) {
          return;
        }

        const hasId = props.some((p) => p === "id" || /[A-Za-z]+Id$/.test(p));

        if (props.includes("body")) {
          seen.add("body");
          parameters.push({
            name: "body",
            source: "body",
            containsObjectId: hasId,
          });
        }

        if (props.includes("query")) {
          seen.add("query");
          parameters.push({
            name: "query",
            source: "query",
            containsObjectId: hasId,
          });
        }

        if (props.includes("params")) {
          seen.add("params");
          parameters.push({
            name: "params",
            source: "params",
            containsObjectId: true,
          });
        }

        if (props.includes("cookies")) {
          seen.add("cookies");
          parameters.push({
            name: "cookies",
            source: "cookie",
            containsObjectId: hasId,
          });
        }
      }

      //check for cookies function
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();
        if (
          Node.isIdentifier(expression) &&
          expression.getText() === "cookies"
        ) {
          if (!seen.has("cookies")) {
            seen.add("cookies");
            parameters.push({
              name: "cookies",
              source: "cookie",
              containsObjectId: false,
            });
          }
        }
      }
    });

    return parameters;
  }
}
