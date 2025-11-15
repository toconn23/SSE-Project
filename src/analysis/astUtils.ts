import {
  Project,
  SourceFile,
  Node,
  CallExpression,
  PropertyAccessExpression,
} from "ts-morph";

export class ASTUtils {
  private project: Project;

  constructor() {
    this.project = new Project({
      skipAddingFilesFromTsConfig: true,
      compilerOptions: {
        allowJs: true,
        jsx: 2,
      },
    });
  }

  createSourceFile(filePath: string, content: string): SourceFile {
    try {
      //remove existing file if it exists
      const existing = this.project.getSourceFile(filePath);
      if (existing) {
        this.project.removeSourceFile(existing);
      }

      return this.project.createSourceFile(filePath, content, {
        overwrite: true,
      });
    } catch (error) {
      console.error("Parse error:", error);
      throw error;
    }
  }

  /**
   * Build a map of function name to function node for same-file lookup
   */
  buildFunctionMap(sourceFile: SourceFile): Map<string, Node> {
    const functionMap = new Map<string, Node>();

    // Function declarations: function myFunc() {}
    sourceFile.getFunctions().forEach((func) => {
      const name = func.getName();
      if (name) {
        functionMap.set(name, func);
      }
    });

    // Variable declarations with function expressions: const myFunc = () => {}
    sourceFile.getVariableDeclarations().forEach((varDecl) => {
      const name = varDecl.getName();
      const initializer = varDecl.getInitializer();
      if (
        initializer &&
        (Node.isArrowFunction(initializer) ||
          Node.isFunctionExpression(initializer))
      ) {
        functionMap.set(name, initializer);
      }
    });

    return functionMap;
  }

  /**
   * Extract direct function calls with only depth 1
   */
  extractDirectCalls(node: Node): string[] {
    const calls = new Set<string>();

    node.forEachDescendant((descendant) => {
      if (Node.isCallExpression(descendant)) {
        const expression = descendant.getExpression();
        // Only collect simple identifier calls: doThing() ignores obj.doThing()
        if (Node.isIdentifier(expression)) {
          calls.add(expression.getText());
        }
      }
    });

    return Array.from(calls);
  }

  /**
   * Find the function/handler for a specific HTTP method
   */
  findMethodHandler(sourceFile: SourceFile, method: string): Node | null {
    //check for exported function declarations
    const exportedDeclarations = sourceFile.getExportedDeclarations();
    const methodDeclarations = exportedDeclarations.get(method);

    if (methodDeclarations && methodDeclarations.length > 0) {
      const decl = methodDeclarations[0];
      if (
        Node.isFunctionDeclaration(decl) ||
        Node.isArrowFunction(decl) ||
        Node.isFunctionExpression(decl)
      ) {
        return decl;
      }
      //check variable declaration like export const GET = () => {}
      if (Node.isVariableDeclaration(decl)) {
        const initializer = decl.getInitializer();
        if (initializer) {
          return initializer;
        }
      }
    }

    //if not found, check for variable declarations named after the method
    for (const varDecl of sourceFile.getVariableDeclarations()) {
      if (varDecl.getName() === method) {
        const initializer = varDecl.getInitializer();
        if (initializer) {
          return initializer;
        }
      }
    }

    return null;
  }

  extractHttpMethods(sourceFile: SourceFile): string[] {
    const methods: string[] = [];
    const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

    //check exported declarations
    const exportedDeclarations = sourceFile.getExportedDeclarations();

    exportedDeclarations.forEach((declarations, name) => {
      if (httpMethods.includes(name)) {
        methods.push(name);
      }
    });

    return [...new Set(methods)];
  }

  getCallExpressionName(node: CallExpression): string {
    const expression = node.getExpression();

    if (Node.isIdentifier(expression)) {
      return expression.getText();
    }

    //Property access expression represents property access: db.user.delete
    if (Node.isPropertyAccessExpression(expression)) {
      return expression.getText();
    }

    return "";
  }

  /**
   * Returns the chain of property identifiers in a PropertyAccessExpression like request.body.userId
   */
  getPropertyAccessChain(node: PropertyAccessExpression): string[] {
    const parts: string[] = [];
    let current: Node = node;

    while (Node.isPropertyAccessExpression(current)) {
      const name = current.getName();
      parts.unshift(name);

      const expression = current.getExpression();
      if (Node.isIdentifier(expression)) {
        parts.unshift(expression.getText());
        break;
      }
      current = expression;
    }

    return parts;
  }
}
