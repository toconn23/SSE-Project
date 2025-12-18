import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "../../../../lib/session";

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

const db = {
  user: {
    findMany: () => users,
  },
};

export async function GET(request: NextRequest) {
  const session = getServerSession(request);

  if (!session) {
    return NextResponse.json(
      { error: "Unauthorized - Authentication required" },
      { status: 401 }
    );
  }

  // VULNERABILITY: Non-admin users can read entire user table
  // Should check: if (session.role !== "admin") { return 403 }
  const allUsers = db.user.findMany();

  return NextResponse.json(allUsers);
}
