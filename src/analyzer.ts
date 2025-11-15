import { Node, SourceFile } from "ts-morph";
import { RouteInfo, Sink, MethodDetails, SecurityConfig } from "./types";
import { ASTUtils } from "./analysis/astUtils";
import { SinkDetector } from "./analysis/sinkDetector";
import { AuthAnalyzer } from "./analysis/authAnalyzer";
import { ControlFlowAnalyzer } from "./analysis/controlFlowAnalyzer";
import { ParameterExtractor } from "./analysis/parameterExtractor";

export class Analyzer {
  private config: SecurityConfig;
  private astUtils: ASTUtils;
  private sinkDetector: SinkDetector;
  private authAnalyzer: AuthAnalyzer;
  private controlFlowAnalyzer: ControlFlowAnalyzer;
  private parameterExtractor: ParameterExtractor;

  constructor(config: SecurityConfig = {}) {
    this.config = config;
    this.astUtils = new ASTUtils();
    this.sinkDetector = new SinkDetector(this.astUtils);
    this.authAnalyzer = new AuthAnalyzer(config);
    this.controlFlowAnalyzer = new ControlFlowAnalyzer(this.authAnalyzer);
    this.parameterExtractor = new ParameterExtractor(this.astUtils);
  }

  analyzeRoute(filePath: string, content: string): RouteInfo {
    const sourceFile = this.astUtils.createSourceFile(filePath, content);
    const methods = this.astUtils.extractHttpMethods(sourceFile);
    const functionMap = this.astUtils.buildFunctionMap(sourceFile);
    const middleware = this.authAnalyzer.detectMiddleware(sourceFile);
    const methodDetails = this.analyzeMethods(
      sourceFile,
      methods,
      functionMap,
      middleware
    );

    return {
      filePath,
      method: methods,
      sinks: this.sinkDetector.detectSinks(sourceFile),
      hasAuthentication:
        this.hasAnyAuthentication(sourceFile) ||
        this.authAnalyzer.hasAuthMiddleware(middleware),
      authorizationChecks: this.authAnalyzer.extractAuthChecks(sourceFile),
      parameters: this.parameterExtractor.extractParameters(sourceFile),
      middleware,
      methodDetails,
    };
  }

  private analyzeMethods(
    sourceFile: SourceFile,
    methods: string[],
    functionMap: Map<string, Node>,
    middleware: string[]
  ): MethodDetails[] {
    const methodDetails: MethodDetails[] = [];

    for (const method of methods) {
      const handler = this.astUtils.findMethodHandler(sourceFile, method);
      if (handler) {
        const directSinks = this.sinkDetector.detectSinks(handler);
        const directAuthChecks = this.authAnalyzer.extractAuthChecks(handler);

        //check if direct sinks are protected by auth conditionals
        directSinks.forEach((sink) => {
          sink.isProtected = this.controlFlowAnalyzer.isSinkProtected(
            handler,
            sink
          );
        });
        const hasDirectAuth = directSinks.every((sink) => sink.isProtected);

        //analyze call graph for depth of 1
        const calledFunctions = this.astUtils.extractDirectCalls(handler);
        const indirectSinks: Sink[] = [];
        let hasIndirectAuth = true;
        const indirectAuthChecks = [];

        for (const funcName of calledFunctions) {
          const funcNode = functionMap.get(funcName);
          if (funcNode) {
            const funcSinks = this.sinkDetector.detectSinks(funcNode);

            //check if the function call itself or sinks within function are protected
            const isFunctionCallProtected =
              this.controlFlowAnalyzer.isFunctionCallProtected(
                handler,
                funcName
              );

            funcSinks.forEach((sink) => {
              const isProtected =
                isFunctionCallProtected ||
                this.controlFlowAnalyzer.isSinkProtected(funcNode, sink);
              indirectSinks.push({
                ...sink,
                callPath: [funcName, ...sink.callPath],
                isProtected,
              });

              if (!isProtected) {
                hasIndirectAuth = false;
              }
            });

            const funcAuthChecks =
              this.authAnalyzer.extractAuthChecks(funcNode);
            indirectAuthChecks.push(...funcAuthChecks);
          }
        }

        //combine the direct and indirect results
        const allSinks = [...directSinks, ...indirectSinks];

        //authentication is valid only if all sinks are protected by auth conditionals or auth middleware
        const allSinksProtected =
          (directSinks.length === 0 || hasDirectAuth) &&
          (indirectSinks.length === 0 || hasIndirectAuth);
        const hasAuth =
          allSinksProtected || this.authAnalyzer.hasAuthMiddleware(middleware);

        const allAuthChecks = [...directAuthChecks, ...indirectAuthChecks];

        methodDetails.push({
          method,
          sinks: allSinks,
          hasAuthentication: hasAuth,
          authorizationChecks: allAuthChecks,
        });
      } else {
        //handler should be found, but in case
        console.warn(`Warning: Could not find handler for ${method} method`);
        methodDetails.push({
          method,
          sinks: [],
          hasAuthentication: false,
          authorizationChecks: [],
        });
      }
    }

    return methodDetails;
  }

  private hasAnyAuthentication(sourceFile: SourceFile): boolean {
    let hasAuth = false;

    sourceFile.forEachDescendant((node) => {
      if (this.authAnalyzer.hasAuthPatternInNode(node)) {
        hasAuth = true;
        return true;
      }
    });

    return hasAuth;
  }
}
