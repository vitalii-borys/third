import { WebSocketServer } from "ws";
import Database from "better-sqlite3";
import { randomBytes } from 'crypto';

const db = new Database("database.db");

const sql = (strings, ...values) => {
  return strings.reduce((prev, curr, i) => prev + curr + (values[i] || ""), "");
};

db.exec(sql `CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  contacts TEXT NOT NULL DEFAULT "[]",
  challengeBuffer TEXT NOT NULL,
  userRole TEXT NOT NULL DEFAULT 'user',
  publicKey TEXT NOT NULL
)`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    messageText TEXT NOT NULL,
    username TEXT NOT NULL,
    messageType TEXT NOT NULL CHECK (messageType in ('message', 'delete', 'remove', 'update')),
    messageTime INTEGER NOT NULL
  )
`);

const wss = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const getUser = db.prepare(sql `SELECT * FROM users WHERE username = ?`);
const insertUser = db.prepare(sql `INSERT INTO users (username, publicKey, challengeBuffer, contacts) VALUES (?, ?, ?, ?)`);
const updateContacts = db.prepare(sql `UPDATE users SET contacts = ? WHERE username = ?`);
const insertMessage = db.prepare(sql `INSERT INTO messages (messageText, username, messageType, messageTime) VALUES (?, ?, ?, ?)`);
const deleteMessage = db.prepare(sql`DELETE FROM messages WHERE id = ? AND username = ?`);
const updateMessage = db.prepare(sql`UPDATE messages SET messageText = ? WHERE id = ? AND username = ?`);
const selectedMessages = db.prepare(sql` SELECT * FROM messages WHERE username = ? ORDER BY messageTime ASC`);
const getAllUsers = db.prepare(sql `SELECT * FROM users`);
const getAllMessages = db.prepare(sql` SELECT * FROM messages ORDER BY messageTime ASC`);

wss.on("connection", ws => {
  let buf;
  console.log("Client connected");
  let authenticatedUser = null;

  ws.on("message", async data => {
    let parsed;
    try {
      parsed = JSON.parse(data.toString());
    } catch (error) {
      console.log("Message parsing error", error);
      ws.send(JSON.stringify({"messageType": "error", "messageText": "invalid JSON"}));
      return;
    }
    const timeStamp = Date.now();
    console.log("user sent", parsed.messageType, "type of message");
    switch (parsed.messageType) {
      case "checkUsername": {
        if (parsed.username.length < 3) {
          ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: false, messageText: "is too short."} ));
        } else {
          const existing = getUser.get(parsed.username);
          if (existing) {
            ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: false} ));
            console.log("User", parsed.username, "is not available");
          } else {
            ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: true} ));
          }
        }
      }
      break;
      case "login": {
        const existing = getUser.get(parsed.username);
        if (existing) {
          const challengeMessage = JSON.stringify({messageType: "auth", messageText: buf});
          ws.send(challengeMessage);
          console.log("First challenge is sent to client\n");
        } else {
          ws.send(JSON.stringify({messageType: "error", messageText: `no such user ${parsed.username}`}));
        }
      }
      break;
      case "register": {
        const existing = getUser.get(parsed.username);
        if (existing) {
          console.log("Username", parsed.username, "is taken");
          ws.send(JSON.stringify({messageType: "error", messageText: "username taken"}));
        } else {
          buf = randomBytes(32).toString("hex");
          console.log("The random bytes of data generated is: " + typeof buf + buf, "is buf", parsed.username, "is username", parsed.publicKey, "is public key");
          insertUser.run(parsed.username, parsed.publicKey, buf, "[]");
          console.log("Username", parsed.username, "is written into database");
        }
      }
      break;
      case "challenge": {
        const existing = getUser.get(parsed.username);
        if (existing) {
          const challengeMessage = JSON.stringify({messageType: "auth", messageText: existing.challengeBuffer});
          ws.send(challengeMessage);
          console.log("Challenge is sent to", existing.username, "\n");
        } else {
          console.log("Username", parsed.username, "Challenge failed");
          ws.send(JSON.stringify({messageType: "error", messageText: "Challenge failed"}));
        }
      }
      break;
      case "auth": {
        const user = getUser.get(parsed.username);
        if (user) {
          const publicKeyBuffer = Buffer.from(user.publicKey, 'base64');
          const bufferFromChallange = Buffer.from(user.challengeBuffer);
          const signatureBuffer = Buffer.from(parsed.messageText, 'base64');
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
          try {
            let result = await crypto.subtle.verify(
              "RSASSA-PKCS1-v1_5",
              publicKey,
              signatureBuffer,
              bufferFromChallange
            );
            console.log("result", result);
            if (result) {
              authenticatedUser = getUser.get(parsed.username);
              if (authenticatedUser.userRole === "admin") {
                const payloadObject = {
                  userRole: "admin",
                  messageType: "initialMessage",
                  messages: selectedMessages.all(authenticatedUser.username),
                  user: getUser.get(authenticatedUser.username),
                  users: getAllUsers.all(),
                  allMessages: getAllMessages.all()
                };
                ws.send(JSON.stringify(payloadObject));
                console.log(authenticatedUser.username, "is authenticated as", authenticatedUser.userRole);
              } else if (authenticatedUser.userRole === "user") {
                console.log(authenticatedUser.username, "is authenticated as", authenticatedUser.userRole);
                const payloadObject = {
                  userRole: "user",
                  messageType: "initialMessage",
                  user: getUser.get(authenticatedUser.username),
                  messages: selectedMessages.all(authenticatedUser.username)
                };
                ws.send(JSON.stringify(payloadObject));
                console.log("All messages sent to", authenticatedUser.username);
              } else {
                const payloadObject = {"messageType": "noAuth"};
                ws.send(JSON.stringify(payloadObject));
                console.log("No auth sent to", parsed.username);
              }
            }
          } catch (error) {
            console.log(error);
          }
        } else {
          console.log("No user in database");
          ws.close();
          return;
        }
      }
      break;
      case "message": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify({"messageType": "noAuth"}));
          return;
        } else {
          insertMessage.run(parsed.messageText, authenticatedUser.username, parsed.messageType, timeStamp);
          console.log("Received message id", parsed.id, "from", parsed.username);
        }
      }
      break;
      case "delete": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify({"messageType": "noAuth"}));
          return;
        } else {
          deleteMessage.run(parsed.id, authenticatedUser.username);
          console.log("Message removed", parsed.id);
        }
      }
      break;
      case "update": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify({"messageType": "noAuth"}));
          return;
        } else {
          updateMessage.run(parsed.messageText, parsed.id, authenticatedUser.username);
          console.log("Updated message id", parsed.id, "from", parsed.username);
        }
      }
      break;
      case "addContact": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify({"messageType": "noAuth"}));
          return;
        } else {
          console.log(parsed.username, "asks to update contacts with", parsed.contactUsername);
          const existing = getUser.get(parsed.contactUsername);
          if (existing) {
            if (existing.username === parsed.username) {
              ws.send(JSON.stringify({ "messageType": "noUser", "messageText": "You can not add yourself as contact" }));
              break;
            }
            authenticatedUser = getUser.get(authenticatedUser.username);
            const newContacts = JSON.parse(authenticatedUser.contacts);
            newContacts.push(parsed.contactUsername);
            const newContactsJSON = JSON.stringify(newContacts);
            updateContacts.run(newContactsJSON, authenticatedUser.username);
            const payloadObject = {
              messageType: "userContact",
              username: existing.username,
            };
            ws.send(JSON.stringify(payloadObject));
            console.log(payloadObject, "sent to", parsed.contactUsername);
          } else {
            const errorMessage = "no such user \"" + `${parsed.contactUsername}` + "\"";
            ws.send(JSON.stringify({ "messageType": "noUser", "messageText": errorMessage }));
            console.log(errorMessage);
          }
        }
      }
      break;
    }
  });
  
  ws.on("close", () => {
    console.log("Client disconnected");
  });
  
});
