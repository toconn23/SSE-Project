import { NextRequest } from "next/server";

export interface Session {
  userId: string;
  role: "user" | "admin";
  authenticated: true;
}

// Hardcoded valid session token - matches security-config.json
const VALID_SESSION_TOKEN = "valid-session-token-123";
const ADMIN_SESSION_TOKEN = "admin-session-token-456";

/**
 * Simulates getServerSession by checking the Cookie header
 * Looks for next-auth.session-token=${sessionCookie}
 */
export function getServerSession(request: NextRequest): Session | null {
  const cookieHeader = request.headers.get("cookie");

  if (!cookieHeader) {
    return null;
  }

  // Extract session token from cookie
  const sessionTokenMatch = cookieHeader.match(
    /next-auth\.session-token=([^;]+)/
  );

  if (!sessionTokenMatch) {
    return null;
  }

  const sessionToken = sessionTokenMatch[1];

  // Check if it's the admin session
  if (sessionToken === ADMIN_SESSION_TOKEN) {
    return {
      userId: "admin-user-id",
      role: "admin",
      authenticated: true,
    };
  }

  // Check if it's a valid user session
  if (sessionToken === VALID_SESSION_TOKEN) {
    return {
      userId: "user-123",
      role: "user",
      authenticated: true,
    };
  }

  return null;
}


