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
          const bodyIndex = props.indexOf("body");
          //Extract the property name after the body
          let propertyName = null;
          if (props[bodyIndex + 1]) {
            propertyName = props[bodyIndex + 1];
          }
          const paramKey = `body.${propertyName}`;
          if (!seen.has(paramKey)) {
            if (propertyName) {
              seen.add(paramKey);
            }
            parameters.push({
              name: propertyName ?? "",
              source: "body",
              containsObjectId: hasId,
            });
          }
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
      }
    });

    return parameters;
  }
}
