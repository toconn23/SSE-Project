import { NextRequest, NextResponse } from "next/server";
import { tasks } from "../route";

const db = {
  task: {
    findUnique: (id: string) => tasks.find((t) => t.id === id),
    update: (id: string, data: any) => {
      const index = tasks.findIndex((t) => t.id === id);
      if (index !== -1) {
        tasks[index] = { ...tasks[index], ...data };
        return tasks[index];
      }
      return null;
    },
    delete: (id: string) => {
      const index = tasks.findIndex((t) => t.id === id);
      if (index !== -1) {
        tasks.splice(index, 1);
        return true;
      }
      return false;
    },
  },
};

function getSessionUserId(request: NextRequest): string | null {
  const userId = request.headers.get("x-user-id");
  return userId;
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const sessionUserId = getSessionUserId(request);
  if (!sessionUserId) {
    return NextResponse.json(
      { error: "Unauthorized - Please log in" },
      { status: 401 }
    );
  }

  const task = db.task.findUnique(id);
  if (!task) {
    return NextResponse.json({ error: "Task not found" }, { status: 404 });
  }

  if (task.userId !== sessionUserId) {
    return NextResponse.json(
      { error: "Forbidden - You can only update your own tasks" },
      { status: 403 }
    );
  }

  const body = await request.json();

  const updatedTask = db.task.update(id, {
    ...body,
    userId: task.userId,
    id: task.id,
  });

  return NextResponse.json(updatedTask);
}

//VULNERABILITY: Direct database write without authorization or ownership check
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const task = db.task.findUnique(id);
  if (!task) {
    return NextResponse.json({ error: "Task not found" }, { status: 404 });
  }

  db.task.delete(id);

  return NextResponse.json({ message: "Task deleted" });
}
