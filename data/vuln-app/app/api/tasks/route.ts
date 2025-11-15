import { NextRequest, NextResponse } from "next/server";

export const tasks: any[] = [];

const db = {
  task: {
    findMany: () => tasks,
    create: (data: any) => {
      const newTask = {
        id: Math.random().toString(36).substring(7),
        ...data,
        createdAt: new Date().toISOString(),
      };
      tasks.push(newTask);
      return newTask;
    },
  },
};

export async function GET(request: NextRequest) {
  const allTasks = db.task.findMany();
  return NextResponse.json(allTasks);
}

export async function POST(request: NextRequest) {
  const body = await request.json();

  //VULNERABILITY: Direct database write without authentication
  const newTask = db.task.create({
    title: body.title,
    description: body.description,
    userId: body.userId,
    completed: false,
  });

  return NextResponse.json(newTask, { status: 201 });
}
