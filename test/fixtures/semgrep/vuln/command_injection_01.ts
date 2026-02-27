import { exec } from "node:child_process"

export function runCommand(req: { query: { cmd: string } }) {
  exec(req.query.cmd)
}
