import { WebSocketServer } from "ws";
import Database from "better-sqlite3";
import { randomBytes } from 'crypto';

const db = new Database("database.db");

const sql = (strings, ...values) => {
  return strings.reduce((prev, curr, i) => prev + curr + (values[i] || ""), "");
};

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    username TEXT NOT NULL ,
    messageType TEXT NOT NULL CHECK (messageType in ('message', 'delete', 'remove', 'update')),
    timestamp INTEGER NOT NULL
  )
`);

const wss = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const insertMessage = db.prepare(sql `
  INSERT INTO messages (text, username, messageType, timestamp)
  VALUES (?, ?, ?, ?)
`);

const deleteMessage = db.prepare(sql` DELETE FROM messages WHERE id = ? `);

const updateMessage = db.prepare(sql` UPDATE messages SET text = ? WHERE id = ? `);
const selectedMessages = db.prepare(sql` SELECT * FROM messages WHERE username = ? ORDER BY timestamp ASC`);


wss.on("connection", ws => {
  console.log("Client connected");
  let authenticatedUser = null;

  const buf = randomBytes(32).toString("hex");
  console.log("The random bytes of data generated is: " + typeof buf + buf);
  console.log(selectedMessages.all(authenticatedUser), "are selected messages");
  
  ws.on("message", async data => {
    const parsed = JSON.parse(data.toString());
    const timeStamp = Date.now();
    switch (parsed.messageType) {
      case "hello": {
        const helloMessage = JSON.stringify({"messageType": "auth", "text": buf});
        ws.send(helloMessage);
        console.log(helloMessage, "is sent to client\n");
      }
      break;
      case "auth": {
        const bufferFromChallange = Buffer.from(buf);
        const signatureBuffer = Buffer.from(parsed.text, 'base64');
        const publicKeyBuffer = Buffer.from(parsed.publicKey, 'base64');
        const publicKey = await crypto.subtle.importKey(
          "spki",
          publicKeyBuffer,
          { 
            name: "RSASSA-PKCS1-v1_5", // Must match the verify algorithm
            hash: "SHA-256"
          },
          true,
          ["verify"]
        );
        try {
          let result = await crypto.subtle.verify(
            "RSASSA-PKCS1-v1_5",
            publicKey,
            signatureBuffer,
            bufferFromChallange
            );
            if (result) {
              authenticatedUser = parsed.username;
              console.log(authenticatedUser, "is authenticated");
              const payloadObject = {"messageType": "initialMessage", "messages": selectedMessages.all(authenticatedUser)};
              ws.send(JSON.stringify(payloadObject));
              console.log(payloadObject, "sent to", authenticatedUser);
            }
          } catch (error) {
            console.log(error);
          }
        }
      break;
      case "message": {
        insertMessage.run(parsed.text, parsed.username, parsed.messageType, timeStamp);
        console.log("Received message from", parsed.username);
      }
      break;
      case "delete": {
        deleteMessage.run(parsed.id);
        console.log("Message removed", parsed.id);
      }
      break;
      case "update": {
        updateMessage.run(parsed.text, parsed.id);
        console.log("Updated message from", parsed.username);
      }
      break;
    }
  });
  
  ws.on("close", () => {
    console.log("Client disconnected");
  });
  
});
