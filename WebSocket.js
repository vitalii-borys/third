import { WebSocketServer } from "ws";
import Database from "better-sqlite3";
import { randomBytes } from 'crypto';

const db = new Database("database.db");

const sql = (strings, ...values) => {
  return strings.reduce((prev, curr, i) => prev + curr + (values[i] || ""), "");
};

db.exec(sql `CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  publicKey TEXT NOT NULL
)`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    username TEXT NOT NULL,
    messageType TEXT NOT NULL CHECK (messageType in ('message', 'delete', 'remove', 'update')),
    timestamp INTEGER NOT NULL
  )
`);

const wss = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const getUser = db.prepare(sql `SELECT * FROM users WHERE username = ?`);
const insertUser = db.prepare(sql `INSERT INTO users (username, publicKey) VALUES (?, ?)`);

const insertMessage = db.prepare(sql `INSERT INTO messages (text, username, messageType, timestamp) VALUES (?, ?, ?, ?)`);

const deleteMessage = db.prepare(sql`DELETE FROM messages WHERE id = ?`);

const updateMessage = db.prepare(sql`UPDATE messages SET text = ? WHERE id = ?`);
const selectedMessages = db.prepare(sql` SELECT * FROM messages WHERE username = ? ORDER BY timestamp ASC`);


wss.on("connection", ws => {
  console.log("Client connected");
  let authenticatedUser = null;

  const buf = randomBytes(32).toString("hex");
  console.log("The random bytes of data generated is: " + typeof buf + buf);
  
  ws.on("message", async data => {
    const parsed = JSON.parse(data.toString());
    const timeStamp = Date.now();
    console.log("user sent", parsed);
    switch (parsed.messageType) {
      case "register": {
        const existing = getUser.get(parsed.username);
        if (existing) {
          console.log("Username", parsed.username, "is taken");
          ws.send(JSON.stringify({"messageType": "error", "text": "username taken"}));
        } else {
          console.log(parsed.username, parsed.publicKey);
          insertUser.run(parsed.username, parsed.publicKey);
          console.log("Username", parsed.username, "is written into database");
          const challengeMessage = JSON.stringify({"messageType": "auth", "text": buf});
          ws.send(challengeMessage);
          console.log(challengeMessage, "challenge is sent to client\n");
        }
      }
      break;
      case "challenge": {
        const challengeMessage = JSON.stringify({"messageType": "auth", "text": buf});
        ws.send(challengeMessage);
        console.log(challengeMessage, "challenge is sent to client\n");
      }
      break;
      case "auth": {
        const user = getUser.get(parsed.username);
        console.log("user from database is", user);
        if (!user) {
          ws.close;
          console.log("No user in database");
          return;
        }
        const publicKeyBuffer = Buffer.from(user.publicKey, 'base64');
        const bufferFromChallange = Buffer.from(buf);
        const signatureBuffer = Buffer.from(parsed.text, 'base64');
        const publicKey = await crypto.subtle.importKey(
          "spki",
          publicKeyBuffer,
          { 
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256"
          },
          true,
          ["verify"]
        );
        console.log("publicKey", publicKey);
        try {
          let result = await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            publicKey,
            signatureBuffer,
            bufferFromChallange
          );
          console.log("result", result);
            if (result) {
              authenticatedUser = parsed.username;
              console.log(authenticatedUser, "is authenticated");
              const payloadObject = {"messageType": "initialMessage", "messages": selectedMessages.all(authenticatedUser)};
              ws.send(JSON.stringify(payloadObject));
              console.log(payloadObject, "sent to", authenticatedUser);
            } else {
              const payloadObject = {"messageType": "noAuth"};
              ws.send(JSON.stringify(payloadObject));
              console.log(payloadObject, "sent to", parsed.username);
            }
          } catch (error) {
            console.log(error);
          }
        }
      break;
      case "message": {
        insertMessage.run(parsed.text, authenticatedUser, parsed.messageType, timeStamp);
        console.log("Received message id", parsed.id, "from", parsed.username);
      }
      break;
      case "delete": {
        deleteMessage.run(parsed.id);
        console.log("Message removed", parsed.id);
      }
      break;
      case "update": {
        updateMessage.run(parsed.text, parsed.id);
        console.log("Updated message id", parsed.id, "from", parsed.username);
      }
      break;
    }
  });
  
  ws.on("close", () => {
    console.log("Client disconnected");
  });
  
});
