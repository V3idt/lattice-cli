type Db = {
  query: (statement: string) => Promise<unknown>
}

export async function getUserById(req: { query: { id: string } }, db: Db) {
  const userId = req.query.id
  return db.query("SELECT * FROM users WHERE id = " + userId)
}
