import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { cookies } from "next/headers";

//This file is not used, just added to test the call graph, raw sql, custom roles, cookies, and nextauth

function deleteUserData(userId: string) {
  //Raw SQL with dangerous command
  const result = db.$executeRaw`DELETE FROM user_data WHERE user_id = ${userId}`;
  return result;
}

//helper with custom role check
function checkSuperuser(userRole: string) {
  //custom role from config
  return userRole === "superuser" || userRole === "moderator";
}

export async function DELETE(request: NextRequest) {
  //NextAuth pattern
  const session = await getServerSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  //cookie parameter extraction
  const authToken = cookies().get("auth_token");

  //Custom role check
  if (!checkSuperuser(session.user.role)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { userId } = await request.json();

  //Call to helper with sink
  await deleteUserData(userId);

  return NextResponse.json({ success: true });
}
