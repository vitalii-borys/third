import { WebSocketServer } from "ws";
import Database from "better-sqlite3";
import { randomBytes } from 'crypto';

const db = new Database("database.db");

const sql = (strings, ...values) => {
  return strings.reduce((prev, curr, i) => prev + curr + (values[i] || ""), "");
};

db.exec(sql `CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    challengeBuffer TEXT NOT NULL,
    userRole TEXT NOT NULL DEFAULT 'user',
    publicKey TEXT NOT NULL
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS conversations (
    ID INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    contactusername TEXT NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username),
    FOREIGN KEY (contactusername) REFERENCES users(username)
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    messageText TEXT NOT NULL,
    messageType TEXT NOT NULL CHECK (messageType in ('message', 'delete', 'remove', 'update')),
    messageTime INTEGER NOT NULL,
    conversationID INTEGER NOT NULL,
    senderUsername TEXT NOT NULL,
    FOREIGN KEY (conversationID) REFERENCES conversations(ID),
    FOREIGN KEY (senderUsername) REFERENCES users(username)
  )
`);


const wss = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const getUser = db.prepare(sql `SELECT * FROM users WHERE username = ?`);
const getConversation = db.prepare(sql `SELECT * FROM conversations WHERE (username = ? AND contactUsername = ?) OR (contactUsername = ? AND username = ?)`);
const insertUser = db.prepare(sql `INSERT INTO users (username, publicKey, challengeBuffer) VALUES (?, ?, ?)`);
const insertMessage = db.prepare(sql `INSERT INTO messages (messageText, messageType, messageTime, conversationID, senderUsername) VALUES (?, ?, ?, ?, ?)`);
const insertConversation = db.prepare(sql `INSERT INTO conversations (username, contactUsername) VALUES (?, ?)`);
const deleteMessage = db.prepare(sql`DELETE FROM messages WHERE id = ? AND conversationID = ? AND senderUsername = ?`);
const updateMessage = db.prepare(sql`UPDATE messages SET messageText = ? WHERE id = ? AND conversationID = ? AND senderUsername = ?`);
const getAllUsers = db.prepare(sql `SELECT * FROM users`);
const getAllMessages = db.prepare(sql` SELECT * FROM messages ORDER BY messageTime ASC`);
const selectedMessages = db.prepare(sql`
  SELECT * FROM messages WHERE conversationID IN (
    SELECT ID FROM conversations
    WHERE username = ? OR contactUsername = ?
    )
  ORDER BY messageTime ASC
`);
const selectedConversations = db.prepare(sql`
  SELECT * FROM conversations WHERE username = ?
`);

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
      ws.send(JSON.stringify( {messageType: "error", messageText: "invalid JSON"}));
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
          if (existing !== undefined) {
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
        if (existing !== undefined) {
          const challengeMessage = JSON.stringify( {messageType: "auth", messageText: existing.challengeBuffer} );
          ws.send(challengeMessage);
          console.log("First challenge is sent to client\n");
        } else {
          ws.send(JSON.stringify( {messageType: "error", messageText: `no such user ${parsed.username}`} ));
        }
      }
      break;
      case "register": {
        const existing = getUser.get(parsed.username);
        if (existing !== undefined) {
          console.log("Username", parsed.username, "is taken");
          ws.send(JSON.stringify( {messageType: "error", messageText: "username taken"} ));
        } else {
          buf = randomBytes(32).toString("hex");
          console.log("The random bytes of data generated is: " + typeof buf + buf, "is buf", parsed.username, "is username", parsed.publicKey, "is public key");
          insertUser.run(parsed.username, parsed.publicKey, buf);
          const newUser = getUser.get(parsed.username);
          console.log("Username", newUser, "is written into database");
          ws.send(JSON.stringify({ messageType: "auth", messageText: newUser.challengeBuffer }));
          console.log("Challenge", newUser.challengeBuffer, "is sent to", newUser.username, "\n");
        }
      }
      break;
      case "challenge": {
        const existing = getUser.get(parsed.username);
        if (existing !== undefined) {
          ws.send(JSON.stringify( {messageType: "auth", messageText: existing.challengeBuffer} ));
          console.log("Challenge is sent to", existing.username, "\n");
        } else {
          ws.send(JSON.stringify( {messageType: "error", messageText: "Challenge failed"} ));
          console.log("Username", parsed.username, "Challenge failed");
        }
      }
      break;
      case "auth": {
        const user = getUser.get(parsed.username);
        if (user !== undefined) {
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
                const allConversations = selectedConversations.all(authenticatedUser.username);
                const payloadObject = {
                  userRole: "user",
                  messageType: "initialMessage",
                  user: getUser.get(authenticatedUser.username),
                  conversations: allConversations
                };
                ws.send(JSON.stringify(payloadObject));
                console.log("All conversations sent to", authenticatedUser.username);
              } else {
                ws.send(JSON.stringify( {messageType: "noAuth"} ));
                console.log("No auth sent to", parsed.username);
              }
            }
          } catch (error) {
            console.log(error);
          }
        } else {
          ws.send(JSON.stringify( {messageType: "error", messageText: "You are not in database."} ));
          console.log("No user in database");
        }
      }
      break;
      case "message": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify( {messageType: "noAuth"}));
          return;
        } else {
          const currentContact = getUser.get(parsed.contactUsername);
          if (currentContact !== undefined) {
            const contactConversation = getConversation.get(authenticatedUser.username, currentContact.username, currentContact.username, authenticatedUser.username);
            if (contactConversation !== undefined) {
              const lastMessage = insertMessage.run(parsed.messageText, parsed.messageType, timeStamp, contactConversation.ID, authenticatedUser.username);
              ws.send(JSON.stringify({ messageType: "messageConfirm", id: lastMessage.lastInsertRowid, messageTime: timeStamp }));
              console.log("Received message id", parsed.id, "from", parsed.username, "message in database is:", lastMessage);
            } else {
              console.log("User doesn't belong to conversation");
            }
          } else {
            ws.send(JSON.stringify({ messageType: "error", messageText: "user not found"}));
            console.log("You have no such contact", parsed.contactUsername);
            return;
          }
        }
      }
      break;
      case "delete": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify( {messageType: "noAuth"} ));
          return;
        } else {
          const currentConversation = getConversation.get(authenticatedUser.username, parsed.contactUsername, parsed.contactUsername, authenticatedUser.username);
            if (currentConversation === undefined) {
              ws.send(JSON.stringify( {messageType: "error", messageText: "Conversation not found"} ));
              console.log("Conversation not found");
              break;
            } else {
              deleteMessage.run(parsed.id, currentConversation.ID, authenticatedUser.username);
              console.log("Message removed", parsed.id);
          }
        }
      }
      break;
      case "update": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify( {messageType: "noAuth"} ));
          return;
        } else {
          const currentConversation = getConversation.get(authenticatedUser.username, parsed.contactUsername, parsed.contactUsername, authenticatedUser.username);
          if (currentConversation === undefined) {
              ws.send(JSON.stringify( {messageType: "error", messageText: "Conversation not found"} ));
              console.log("Conversation not found");
              break;
          } else {
            updateMessage.run(parsed.messageText, parsed.id, currentConversation.ID, authenticatedUser.username);
            console.log("Updated message id", parsed.id, "from", parsed.username);
          }
        }
      }
      break;
      case "addConversation": {
        if (!authenticatedUser) {
          ws.send(JSON.stringify( {messageType: "noAuth"} ));
          return;
        } else {
          console.log(parsed.username, "asks to update contacts with", parsed.contactUsername);
          const existing = getUser.get(parsed.contactUsername);
          if (existing !== undefined) {
            if (existing.username === authenticatedUser.username) {
              ws.send(JSON.stringify( {messageType: "noUser", messageText: "You can not add yourself as contact" }));
              break;
            }
            const exists = getConversation.get(authenticatedUser.username, parsed.contactUsername, parsed.contactUsername, authenticatedUser.username);
            if (exists !== undefined) {
              ws.send(JSON.stringify( {messageType: "error", messageText: "Conversation already exists"} ));
              console.log("Conversation already exists");
              break;
            } else {
              insertConversation.run(authenticatedUser.username, parsed.contactUsername);
              ws.send(JSON.stringify( {messageType: "userContact", username: existing.username} ));
              console.log( JSON.stringify({messageType: "userContact", username: existing.username}), "sent to", parsed.username);
            }
          } else {
            const errorMessage = "no such user \"" + `${parsed.contactUsername}` + "\"";
            ws.send(JSON.stringify({ messageType: "noUser", "messageText": errorMessage }));
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
