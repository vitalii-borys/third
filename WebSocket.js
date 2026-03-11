import { WebSocketServer } from "ws";
import Database from "better-sqlite3";

const db = new Database("database.db");

const sql = (strings, ...values) => {
  return strings.reduce((prev, curr, i) => prev + curr + (values[i] || ""), "");
};

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    username TEXT NOT NULL,
    timestamp INTEGER NOT NULL
  )
`);

const wss = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const insertMessage = db.prepare(sql `
  INSERT INTO messages (username, text, timestamp)
  VALUES (?, ?, ?)
`);

wss.on("connection", ws => {
  console.log("Client connected");
  const selectedMessages = db.prepare(sql`
    SELECT *
    FROM messages
    WHERE username = ?
    ORDER BY timestamp ASC;
    `).all('Alice');
  const messages = selectedMessages; 
  console.log(messages);
  
  ws.on("message", data => {
    const parsed = JSON.parse(data.toString());
    insertMessage.run(
      parsed.username,
      parsed.text,
      Date.now()
    );
    console.log("Received message from", parsed.username);
  });
  
  ws.on("close", () => {
    console.log("Client disconnected");
  });
  
  ws.send(JSON.stringify(selectedMessages));
});
