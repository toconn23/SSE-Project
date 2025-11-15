import { Node } from "ts-morph";
import { Sink } from "../types";
import { AuthAnalyzer } from "./authAnalyzer";

export class ControlFlowAnalyzer {
  private authAnalyzer: AuthAnalyzer;

  constructor(authAnalyzer: AuthAnalyzer) {
    this.authAnalyzer = authAnalyzer;
  }

  isSinkProtected(handler: Node, sink: Sink): boolean {
    //find sink node by line number
    let sinkNode: Node | undefined;

    handler.forEachDescendant((node) => {
      if (
        node.getStartLineNumber() ===
        parseInt(sink.location.replace("Line ", ""))
      ) {
        sinkNode = node;
        return true;
      }
    });

    if (!sinkNode) {
      return false;
    }

    //travel through parent to look for conditinals
    let current: Node | undefined = sinkNode;
    while (current) {
      const parent: Node | undefined = current.getParent();
      if (!parent) break;
      //check if parent is an if statement
      if (Node.isIfStatement(parent)) {
        const condition = parent.getExpression();
        if (this.authAnalyzer.hasAuthPatternInNode(condition)) {
          return true;
        }
      }
      //check if parent is a conditional expression
      if (Node.isConditionalExpression(parent)) {
        const condition = parent.getCondition();
        if (this.authAnalyzer.hasAuthPatternInNode(condition)) {
          return true;
        }
      }
      //check for early return
      if (
        Node.isFunctionDeclaration(parent) ||
        Node.isArrowFunction(parent) ||
        Node.isFunctionExpression(parent)
      ) {
        if (this.hasEarlyAuthReturn(parent, sinkNode)) {
          return true;
        }
        break;
      }
      current = parent;
    }

    return false;
  }

  isFunctionCallProtected(handler: Node, functionName: string): boolean {
    let isProtected = false;

    handler.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();
        if (
          Node.isIdentifier(expression) &&
          expression.getText() === functionName
        ) {
          //found the function call, see if in an auth conditional
          let current: Node | undefined = node;
          while (current) {
            const parent = current.getParent();
            if (!parent) break;

            if (Node.isIfStatement(parent)) {
              const condition = parent.getExpression();
              if (this.authAnalyzer.hasAuthPatternInNode(condition)) {
                isProtected = true;
                return true; // Stop searching
              }
            }

            if (
              Node.isFunctionDeclaration(parent) ||
              Node.isArrowFunction(parent) ||
              Node.isFunctionExpression(parent)
            ) {
              //check for early auth returns
              if (this.hasEarlyAuthReturn(parent, node)) {
                isProtected = true;
                return true;
              }
              break;
            }

            current = parent;
          }
        }
      }
    });

    return isProtected;
  }

  private hasEarlyAuthReturn(functionNode: Node, targetNode: Node): boolean {
    const targetLine = targetNode.getStartLineNumber();
    let hasEarlyReturn = false;

    functionNode.forEachDescendant((node) => {
      //Only check nodes before the target
      if (node.getStartLineNumber() >= targetLine) {
        return;
      }

      if (Node.isReturnStatement(node)) {
        //see if return is in if statement with auth check
        let current: Node | undefined = node;
        while (current && current !== functionNode) {
          const parent = current.getParent();
          if (!parent) break;

          if (Node.isIfStatement(parent)) {
            const condition = parent.getExpression();
            if (this.authAnalyzer.hasAuthPatternInNode(condition)) {
              //Check if the condition is negated
              const conditionText = condition.getText();
              if (conditionText.includes("!")) {
                hasEarlyReturn = true;
                return true;
              }
            }
          }

          current = parent;
        }
      }
    });

    return hasEarlyReturn;
  }
}
