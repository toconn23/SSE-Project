import { NextRequest, NextResponse } from "next/server";
import { tasks } from "../route";

const db = {
  task: {
    findMany: (filter?: any) => {
      if (filter && filter.userId) {
        return tasks.filter((t) => t.userId === filter.userId);
      }
      return tasks;
    },
  },
};

function getAuthenticatedUser(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  const sessionToken = request.headers.get("authorization");

  if (!userId || !sessionToken) {
    return null;
  }

  return { userId, authenticated: true };
}

export async function GET(request: NextRequest) {
  const user = getAuthenticatedUser(request);

  // if (!user) {
  //   return NextResponse.json(
  //     { error: "Unauthorized - Authentication required" },
  //     { status: 401 }
  //   );
  // }

  const userTasks = db.user.findMany({ userId: user.userId });

  return NextResponse.json(userTasks);
}
