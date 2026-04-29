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
    serverPublicKey TEXT NOT NULL,
    userPublicKey TEXT NOT NULL
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS conversations (
    ID INTEGER PRIMARY KEY
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS conversationKeys (
    groupKey TEXT NOT NULL,
    conversationID INTEGER NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (username, conversationID),
    FOREIGN KEY (username) REFERENCES users(username),
    FOREIGN KEY (conversationID) REFERENCES conversations(ID)
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS conversationParticipants (
    username TEXT NOT NULL,
    conversationID INTEGER NOT NULL,
    PRIMARY KEY (username, conversationID),
    FOREIGN KEY (username) REFERENCES users(username),
    FOREIGN KEY (conversationID) REFERENCES conversations(ID)
  )
`);

db.exec(sql`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    messageText TEXT NOT NULL,
    messageType TEXT NOT NULL CHECK (messageType in ('message', 'delete', 'remove', 'update')),
    messageTime INTEGER NOT NULL,
    senderUsername TEXT NOT NULL,
    conversationID INTEGER NOT NULL,
    FOREIGN KEY (conversationID) REFERENCES conversations(ID),
    FOREIGN KEY (senderUsername) REFERENCES users(username)
  )
`);

const ws = new WebSocketServer({ port: 8080 });
console.log("WebSocket server listening on 8080");

const insertConversationParticipantGroupKey = db.prepare(sql `INSERT INTO conversationKeys (username, groupKey, conversationID) VALUES (?, ?, ?)`);
const getConversationKeyForUser = db.prepare(sql `SELECT groupKey FROM conversationKeys WHERE conversationID = ? AND username = ?`);
const getUser = db.prepare(sql `SELECT * FROM users WHERE username = ?`);
const getUserPublicKey = db.prepare(sql `SELECT userPublicKey FROM users WHERE username = ?`);
const insertUser = db.prepare(sql `INSERT INTO users (username, serverPublicKey, userPublicKey, challengeBuffer) VALUES (?, ?, ?, ?)`);
const insertMessage = db.prepare(sql `INSERT INTO messages (messageText, messageType, messageTime, senderUsername, conversationID) VALUES (?, ?, ?, ?, ?)`);
const getMessage = db.prepare(sql `SELECT messageText FROM messages WHERE senderUsername = ? AND id = ?`);
const insertConversationID = db.prepare(sql `INSERT INTO conversations (ID) VALUES (NULL)`);
const insertConversationParticipants = db.prepare(sql `INSERT INTO conversationParticipants (username, conversationID) VALUES (?, ?)`);
const deleteMessage = db.prepare(sql`DELETE FROM messages WHERE id = ? AND senderUsername = ?`);
const updateMessage = db.prepare(sql`UPDATE messages SET messageText = ? WHERE id = ? AND senderUsername = ?`);
const getAllUsers = db.prepare(sql `SELECT * FROM users`);
const getAllUserConversations = db.prepare(sql `SELECT * FROM conversationParticipants WHERE username = ?`);
const getConversationID = db.prepare(sql `SELECT conversationID FROM conversationParticipants WHERE conversationID = ?`);
const getTwoUsersConversationID = db.prepare(sql `SELECT conversationID FROM conversationParticipants WHERE username = ? INTERSECT SELECT conversationID FROM conversationParticipants WHERE  username = ?`);
const getConversationParticipant = db.prepare(sql `SELECT * FROM conversationParticipants WHERE conversationID = ? AND username = ?`);
const selectedMessages = db.prepare(sql`SELECT * FROM messages WHERE conversationID = ? ORDER BY messageTime ASC`);
const getParticipantsOfID = db.prepare(sql`SELECT username FROM conversationParticipants WHERE conversationID = ?`);

const getUserConversationsAndMessages = (username) => {
  const currentConversations = getAllUserConversations.all(username);
  let userFullMessagesHistory = [];
  currentConversations.forEach(conversation => {
    const conversationIDsAndParticipants = getParticipantsOfID.all(conversation.conversationID);
    const conversationParticipants = [];
    conversationIDsAndParticipants.forEach(participant => {
      const participantUser = getUser.get(participant.username);
      conversationParticipants.push( {username: participantUser.username, publicKey: participantUser.userPublicKey} );
    });
    const conversationMessages = selectedMessages.all(conversation.conversationID);
    const userMessages = [];
    conversationMessages.forEach(message => {
      userMessages.push(message);
    });
    const groupKey = getConversationKeyForUser.get(conversation.conversationID, username);
    console.log("groupKey is ", groupKey?.groupKey);
    const conversationObject = {
      conversationID: conversation.conversationID,
      messages: userMessages,
      participants: conversationParticipants,
      groupKey: groupKey?.groupKey
    }
    userFullMessagesHistory.push(conversationObject);
  });
  return userFullMessagesHistory;
}

ws.on("connection", ws => {
  console.log("Client connected");
  let authenticatedUser = null;

  ws.on("message", async data => {
    try {
      const parsed = JSON.parse(data.toString());
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
            const buf = randomBytes(32).toString("hex");
            console.log("The random bytes of data generated is: " + typeof buf + buf, "is buf", parsed.username, "is username", parsed.serverPublicKey, "is serverPublicKey");
            insertUser.run(parsed.username, parsed.serverPublicKey, parsed.userPublicKey, buf);
            const newUser = getUser.get(parsed.username);
            console.log("Username", newUser, "is written into database");
            const notesID = insertConversationID.run();
            insertConversationParticipants.run(parsed.username, notesID.lastInsertRowid); // My notes
            insertConversationParticipantGroupKey.run(parsed.username, parsed.myGroupKey, notesID.lastInsertRowid);
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
            const serverPublicKeyBuffer = Buffer.from(user.serverPublicKey, 'base64');
            const bufferFromChallange = Buffer.from(user.challengeBuffer);
            const signatureBuffer = Buffer.from(parsed.messageText, 'base64');
            const serverPublicKey = await crypto.subtle.importKey(
              "spki",
              serverPublicKeyBuffer,
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
                serverPublicKey,
                signatureBuffer,
                bufferFromChallange
              );
              //console.log("result", result);
              if (result) {
                authenticatedUser = getUser.get(parsed.username);
                if (authenticatedUser.userRole === "admin") {
                  const userData = getUserConversationsAndMessages(authenticatedUser.username);
                  const payloadObject = {
                    userRole: "admin",
                    messageType: "initialMessage",
                    conversations: userData,
                    user: getUser.get(authenticatedUser.username),
                    users: getAllUsers.all()
                  };
                  ws.send(JSON.stringify(payloadObject));
                  console.log(payloadObject, "is sent to", authenticatedUser.username);
                  console.log(authenticatedUser.username, "is authenticated as", authenticatedUser.userRole);
                } else if (authenticatedUser.userRole === "user") {
                  const userData = getUserConversationsAndMessages(authenticatedUser.username);
                  const payloadObject = {
                    userRole: "user",
                    messageType: "initialMessage",
                    user: authenticatedUser,
                    conversations: userData
                  }
                  ws.send(JSON.stringify(payloadObject));
                  console.log(payloadObject, "is sent to", authenticatedUser.username);
                  console.log("All conversations sent to", authenticatedUser.username, "\n");
                } else {
                  ws.send(JSON.stringify( {messageType: "noAuth"} ));
                  console.log("No auth sent to", authenticatedUser.username);
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
            const currentConversationID = getConversationID.get(parsed.conversationID);
            if (currentConversationID !== undefined) {
              const participant = getConversationParticipant.get(currentConversationID.conversationID, authenticatedUser.username);
              if (participant !== undefined) {
                const lastMessage = insertMessage.run(parsed.messageText, parsed.messageType, timeStamp, authenticatedUser.username, currentConversationID.conversationID,);
                const databaseMessage = getMessage.get(authenticatedUser.username, lastMessage.lastInsertRowid);
                console.log("Received message from", parsed.username, ". Message in database is:", databaseMessage);
                const payloadObject = JSON.stringify({
                  messageType: "messageConfirm",
                  id: lastMessage.lastInsertRowid,
                  messageText: databaseMessage.messageText,
                  messageTime: timeStamp,
                  conversationID: currentConversationID.conversationID });
                ws.send(payloadObject);
                console.log(payloadObject, "sent to", authenticatedUser.username);
              } else {
                ws.send(JSON.stringify( {messageType: "error", messageText: "User doesn't belong to conversation"} ));
                console.log("User doesn't belong to conversation");
              }
            } else {
              ws.send(JSON.stringify( {messageType: "error", messageText: "Conversation not found"} ));
              console.log("Conversation ", parsed.conversationID, " not found");
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
            deleteMessage.run(parsed.id, authenticatedUser.username);
            console.log("Message removed", parsed.id);
          }
        }
        break;
        case "update": {
          if (!authenticatedUser) {
            ws.send(JSON.stringify( {messageType: "noAuth"} ));
            return;
          } else {
            updateMessage.run(parsed.messageText, parsed.id, authenticatedUser.username);
            console.log("Updated message id", parsed.id, "from", parsed.username);
          }
        }
        break;
        case "addConversation": {
          if (!authenticatedUser) {
            ws.send(JSON.stringify( {messageType: "noAuth"} ));
            return;
          } else {
            console.log(parsed.username, "asks to create new chat with", parsed.contactUsername);
            const existing = getUser.get(parsed.contactUsername);
            if (existing !== undefined) {
              if (existing.username === authenticatedUser.username) {
                ws.send(JSON.stringify( {messageType: "noUser", messageText: "You can not add yourself as contact" }));
                break;
              }
              const existingConversation = getTwoUsersConversationID.get(authenticatedUser.username, parsed.contactUsername);
              if (existingConversation !== undefined) {
                ws.send(JSON.stringify( {messageType: "noUser", messageText: "Conversation already exists" }));
                console.log("Conversation already exists");
                break;
              } else {
                const newConversationID = insertConversationID.run();
                insertConversationParticipants.run(authenticatedUser.username, newConversationID.lastInsertRowid);
                insertConversationParticipants.run(parsed.contactUsername, newConversationID.lastInsertRowid);
                insertConversationParticipantGroupKey.run(parsed.contactUsername, parsed.groupKey, newConversationID.lastInsertRowid);
                insertConversationParticipantGroupKey.run(authenticatedUser.username, parsed.myGroupKey, newConversationID.lastInsertRowid);
                const userData = getUserConversationsAndMessages(authenticatedUser.username);
                const payloadObject = {
                  userRole: "user",
                  messageType: "userContact",
                  user: getUser.get(authenticatedUser.username),
                  messages: userData
                }
                ws.send(JSON.stringify(payloadObject));
                console.log(payloadObject, "sent to", authenticatedUser.username);
              }
            } else {
              const errorMessage = "no such user \"" + `${parsed.contactUsername}` + "\"";
              ws.send(JSON.stringify( {messageType: "noUser", messageText: errorMessage} ));
              console.log(errorMessage);
            }
          }
        }
        break;
        case "getUserPublicKey": {
          if (!authenticatedUser) {
            ws.send(JSON.stringify( {messageType: "noAuth"} ));
            return;
          } else {
            console.log(authenticatedUser.username, "asks for public key for", parsed.username);
            const existing = getUser.get(parsed.username);
            if (existing !== undefined) {
              const userPublicKeyResult = getUserPublicKey.get(parsed.username);
              ws.send(JSON.stringify( {messageType: "getUserPublicKey", username: parsed.username, publicKey: userPublicKeyResult.userPublicKey} ));
              console.log(userPublicKeyResult, "sent to", authenticatedUser.username);
            } else {
              ws.send(JSON.stringify( {messageType: "error", messageText: `no such user ${parsed.username}`} ));
              console.log(`no such user ${parsed.username}`);
            }
          }
        }
        break;
        case "addGroupConversation": {
          if (!authenticatedUser) {
            ws.send(JSON.stringify( {messageType: "noAuth"} ));
            return;
          } else {
            const arrayOfContactUsernames = [];
            parsed.arrayOfContacts.forEach(contact => {
              arrayOfContactUsernames.push(contact.username);
            });
            console.log(parsed.username, "asks to update contacts with", String(arrayOfContactUsernames));
            let allValid = true;
            for (const contact of parsed.arrayOfContacts) {
              const existing = getUser.get(contact.username);
              if (!existing) {
                const errorMessage = "no such user \"" + `${contact.username}` + "\"";
                console.log(errorMessage);
                ws.send(JSON.stringify( {messageType: "noUser", messageText: errorMessage} ));
                allValid = false;
                break;
              }
            }
            if (allValid) {
              const newConversationID = insertConversationID.run();
              insertConversationParticipants.run(authenticatedUser.username, newConversationID.lastInsertRowid);
              insertConversationParticipantGroupKey.run(authenticatedUser.username, parsed.myGroupKey, newConversationID.lastInsertRowid);
              parsed.arrayOfContacts.forEach(contact => {
                insertConversationParticipants.run(contact.username, newConversationID.lastInsertRowid);
                insertConversationParticipantGroupKey.run(contact.username, contact.groupKey, newConversationID.lastInsertRowid);
              });
              const conversationIDsParticipants = getParticipantsOfID.all(newConversationID.lastInsertRowid);
              const conversationParticipants = [];
              conversationIDsParticipants.forEach(participant => {
                const participantUser = getUser.get(participant.username);
                conversationParticipants.push( {username: participantUser.username, publicKey: participantUser.userPublicKey} );
              });
              const groupKey = getConversationKeyForUser.get(newConversationID.lastInsertRowid, authenticatedUser.username);
              const conversationObject = {
                messageType: "userContact",
                conversationID: newConversationID.lastInsertRowid,
                participants: conversationParticipants,
                groupKey: groupKey.groupKey
              }
              ws.send(JSON.stringify(conversationObject));
              console.log(conversationObject, "sent to", authenticatedUser.username);
            }
          }
        }
        break;
      }
    } catch (error) {
      console.log("Message parsing error", error);
      ws.send(JSON.stringify( {messageType: "error", messageText: "invalid JSON"}));
      return;
    }
  });
  
  ws.on("close", () => {
    console.log("Client disconnected");
  });
  
});
