"use client";
import { useState, useEffect } from "react";

interface Task {
  id: string;
  title: string;
  description: string;
  completed: boolean;
  userId: string;
}

export default function Home() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [userId, setUserId] = useState("user1");

  useEffect(() => {
    fetchTasks();
  }, []);

  const fetchTasks = async () => {
    const response = await fetch("/api/tasks");
    if (response.ok) {
      const data = await response.json();
      setTasks(data);
    }
  };

  const createTask = async () => {
    const response = await fetch("/api/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, description, userId }),
    });
    if (response.ok) {
      setTitle("");
      setDescription("");
      fetchTasks();
    }
  };

  const deleteTask = async (taskId: string) => {
    await fetch(`/api/tasks/${taskId}`, { method: "DELETE" });
    fetchTasks();
  };

  const updateTask = async (taskId: string, updates: Partial<Task>) => {
    await fetch(`/api/tasks/${taskId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    fetchTasks();
  };

  return (
    <div style={{ padding: "20px", maxWidth: "800px", margin: "0 auto" }}>
      <h1>Task Manager</h1>

      <div
        style={{
          marginBottom: "20px",
          padding: "15px",
          border: "1px solid #ddd",
        }}
      >
        <h2>Current User: {userId}</h2>
        <button onClick={() => setUserId("user1")} className="btn-primary">
          Switch to User 1
        </button>
        <button onClick={() => setUserId("user2")} className="btn-secondary">
          Switch to User 2
        </button>
      </div>

      <div
        style={{
          marginBottom: "30px",
          padding: "15px",
          border: "1px solid #ddd",
        }}
      >
        <h2>Create New Task</h2>
        <input
          type="text"
          placeholder="Task title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          style={{ width: "100%", padding: "8px", marginBottom: "10px" }}
        />
        <input
          type="text"
          placeholder="Task description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          style={{ width: "100%", padding: "8px", marginBottom: "10px" }}
        />
        <button onClick={createTask} className="btn-primary">
          Create Task
        </button>
      </div>

      <div>
        <h2>Tasks</h2>
        {tasks.map((task) => (
          <div
            key={task.id}
            style={{
              padding: "15px",
              marginBottom: "10px",
              border: "1px solid #ddd",
              backgroundColor: task.completed ? "#f0f0f0" : "white",
            }}
          >
            <h3>{task.title}</h3>
            <p>{task.description}</p>
            <p style={{ fontSize: "12px", color: "#666" }}>
              Owner: {task.userId} | ID: {task.id}
            </p>
            <button
              onClick={() =>
                updateTask(task.id, { completed: !task.completed })
              }
              className="btn-secondary"
            >
              {task.completed ? "Mark Incomplete" : "Mark Complete"}
            </button>
            <button onClick={() => deleteTask(task.id)} className="btn-danger">
              Delete Task
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
