import { exec } from "node:child_process"

const ALLOWED_COMMANDS: Record<string, string> = {
  status: "uptime",
  disk: "df -h"
}

export function runCommand(req: { query: { action: string } }) {
  const command = ALLOWED_COMMANDS[req.query.action]
  if (!command) {
    throw new Error("Invalid action")
  }
  exec(command)
}
