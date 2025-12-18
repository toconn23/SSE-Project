import * as fc from "fast-check";
import { RouteInfo, MethodDetails, EndpointTestResult } from "../types";

export function containsUserData(body: any): boolean {
  if (!body) return false;

  //sensitive user fields that indicate user data exposure.
  const sensitiveFields = ["emailverified", "password", "passwordhash"];

  //Check if body is an array of users
  if (Array.isArray(body)) {
    //if have multiple records, check if any contain sensitive fields
    return body.some((item) => {
      if (typeof item === "object" && item !== null) {
        return Object.keys(item).some((key) =>
          sensitiveFields.includes(key.toLowerCase())
        );
      }
      return false;
    });
  }
  // check if body is a one user object
  else if (typeof body === "object" && body !== null) {
    return Object.keys(body).some((key) =>
      sensitiveFields.includes(key.toLowerCase())
    );
  }

  return false;
}

export async function fuzzEndpoint(
  baseUrl: string,
  routePath: string,
  method: string,
  fuzzCase: { headers: Record<string, string>; body?: any }
): Promise<EndpointTestResult> {
  const url = buildUrl(baseUrl, routePath);

  try {
    const request = {
      url,
      method,
      headers: fuzzCase.headers,
      body: fuzzCase.body,
    };

    const response = await makeRequest(request);

    return {
      request,
      response,
    };
  } catch (error) {
    const request = {
      url,
      method,
      headers: fuzzCase.headers,
      body: fuzzCase.body,
    };

    return {
      request,
      response: {
        status: 0,
        body: null,
      },
      error: String(error),
    };
  }
}

export function generateFuzzCases(
  route: RouteInfo,
  methodDetail: MethodDetails
): Array<{
  headers: Record<string, string>;
  body?: any;
}> {
  const cases: Array<{
    headers: Record<string, string>;
    body?: any;
  }> = [];

  //these are sample inputs for different types that may be needed in the request
  const samples = fc.sample(
    fc.record({
      stringValue: fc.string({ minLength: 1, maxLength: 100 }),
      //   numberValue: fc.integer({ min: 0, max: 1000 }),
      //   boolValue: fc.boolean(),
      //assume object id is number b/c if not, probably won't guess it anyway
      objectId: fc.integer({ min: 0, max: 1000 }),
    }),
    { numRuns: 1000 }
  );

  // Convert samples into test cases based on route parameters from static analysis
  for (const sample of samples) {
    const testCase: {
      headers: Record<string, string>;
      body?: any;
    } = {
      headers: {
        "Content-Type": "application/json",
      },
    };

    //find parameters that are in the body
    const bodyParams = route.parameters.filter((p) => p.source === "body");
    if (bodyParams.length > 0) {
      testCase.body = {};
      //iterate through all parameters in body and add values for them
      for (const param of bodyParams) {
        //skip parameters that don't know name for
        if (param.name === "") {
          continue;
        }
        //if probable object id, use id sample, otherwise use a random sample from one of the types
        if (param.containsObjectId) {
          testCase.body[param.name] = sample.objectId;
        } else {
          //don't know the type of this parameter, so try string, number, and bool
          testCase.body[param.name] = fc.sample(
            fc.oneof(
              fc.constant(sample.stringValue),
              fc.lorem()
              //   fc.constant(sample.numberValue),
              //   fc.constant(sample.boolValue)
            ),
            1
          )[0];
        }
      }
    }

    cases.push(testCase);
  }

  return cases;
}

/**
 * Extracts the API route path from the file path
 */
export function getRoutePath(filePath: string): string {
  let path = filePath.replace(/\\/g, "/"); //normalize path separator for windows
  const apiIndex = path.indexOf("/api/");
  if (apiIndex === -1) {
    return "/api";
  }
  path = path.substring(apiIndex);
  //get rid of route.ts(x)
  path = path.replace(/\/route\.(ts|tsx)$/, "");
  return path || "/api";
}

/**
 * Builds the full URL for a route path
 */
export function buildUrl(baseUrl: string, routePath: string): string {
  return `${baseUrl}${routePath}`;
}

/**
 * Makes an HTTP request to the endpoint
 */
export async function makeRequest(request: {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: any;
}): Promise<{ status: number; body?: any }> {
  try {
    const options: RequestInit = {
      method: request.method,
      headers: request.headers,
    };

    if (
      request.body &&
      (request.method === "POST" ||
        request.method === "PUT" ||
        request.method === "DELETE")
    ) {
      options.body = JSON.stringify(request.body);
    }

    const response = await fetch(request.url, options);
    const status = response.status;

    // Read the body text first, then try to parse as JSON
    const bodyText = await response.text();
    let body;

    if (bodyText) {
      try {
        body = JSON.parse(bodyText);
      } catch {
        body = bodyText;
      }
    }

    return {
      status,
      body,
    };
  } catch (error) {
    console.error(`Request failed: ${error}`);
    throw error;
  }
}
