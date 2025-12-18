import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "../../../../lib/session";
import securityConfig from "../../../../security-config.json";

/**
 * A safe endpoint that:
 * 1. Reads the user table (has user_table_read sink)
 * 2. Returns 200 status
 * 3. BUT does NOT expose sensitive user data in response
 */
export async function GET(request: NextRequest) {
  // Check if user is authenticated (non-admin session)
  const session = getServerSession(request, securityConfig.sessionTokens.user);

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Simulate reading from user table - this creates a user_table_read sink
  // In production: const users = await db.users.findMany();
  const userQuery = { findMany: () => [] };
  const userData = userQuery.findMany(); // Triggers user_table_read sink

  // Mock user database
  const users = [
    {
      id: "user-123",
      name: "Regular User",
      email: "user@example.com",
      role: "user",
    },
    {
      id: "user-456",
      name: "Another User",
      email: "another@example.com",
      role: "user",
    },
    {
      id: "admin-user-id",
      name: "Admin User",
      email: "admin@example.com",
      role: "admin",
    },
  ];

  //Safe: Check if user is admin before exposing data
  if (session.user.role !== "admin") {
    // Return success status but NO sensitive user data
    return NextResponse.json(
      {
        message: "Access restricted to admins",
        userCount: users.length, // Only expose non-sensitive metadata
      },
      { status: 200 }
    );
  }

  // Admin can see all user data
  return NextResponse.json(users);
}
