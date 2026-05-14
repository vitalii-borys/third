import { WebSocketServer, WebSocket } from "ws";
import Database from "better-sqlite3";
import { randomBytes } from 'crypto';
import { createServer } from "https";
//import { readFile, readFileSync } from "fs";
import { extname, resolve } from "path";
import {readFile, readFileSync} from "fs";

const certificate = readFileSync("./cert.pem");
const certificateKey = readFileSync("./key.pem");
const ROOT = resolve("./public");
const mimeTypes = {
  ".html": "text/html",
  ".js":   "application/javascript",
  ".css":  "text/css",
  ".png":  "image/png",
  ".json": "application/json",
};

const userNameRegex = /^[a-zA-Zа-яА-Я0-9_-]{3,20}$/u;

const httpsServer = createServer({ cert: certificate, key: certificateKey},(req, res) => {
    let decodedUrl = null;
    try {
      decodedUrl = decodeURIComponent(req.url);
    } catch (error) {
      console.log("wrong decodedUrl is", decodedUrl);
      res.writeHead(400);
      res.end("Bad request");
      console.log(error);
      return;
    }
    const filePath = decodedUrl === "/" ? resolve(ROOT + "/index.html") : resolve(ROOT + decodedUrl);
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }
    const ext = extname(filePath);
    const contentType = mimeTypes[ext] || "application/octet-stream";

    readFile(filePath, (err, data) => {
      if (err) {
          res.writeHead(404);
          res.end("Not found");
          return;
      }
      res.writeHead(200, { "Content-Type": contentType });
      res.end(data);
    });
});

const activeClients = new Map();
const ws = new WebSocketServer({ server: httpsServer });
console.log("WebSocket server listening on 8080");
httpsServer.listen(8080, () => console.log("https://192.168.0.222:8080/", "\n"));

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
const updateChallengeBuffer = db.prepare(sql`UPDATE users SET challengeBuffer = ? WHERE username = ?`);

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
    //console.log("groupKey for", conversation.conversationID, "is ", groupKey?.groupKey.slice(0, 4));
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
  const requireAuth = () => {
    if (!authenticatedUser) {
      ws.send(JSON.stringify( {messageType: "noAuth", messageText: "No authentication"}));
      return false;
    }
    return true;
  };

  ws.on("message", async data => {
    try {
      const parsed = JSON.parse(data.toString());
      const timeStamp = Date.now();
      console.log(parsed.username, " sent ", parsed.messageType, " type of message");
      switch (parsed.messageType) {
        case "checkUsername": {
          const correctUsername = userNameRegex.test(parsed.username);
          console.log(parsed.username, " is correct username? ", correctUsername);
          if (parsed.username.length < 3) {
            ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: false, messageText: "is too short."} ));
          } else if (parsed.username.length > 20) {
            ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: false, messageText: "is too long."} ));
          } else {
            if (!correctUsername) {
              ws.send(JSON.stringify({ messageType: "checkUsername", username: parsed.username, available: false, messageText: "can not contain special charachters" }))
              return;
            }
            const existing = getUser.get(parsed.username);
            if (existing !== undefined) {
              ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: false, messageText: "is not available."} ));
              console.log("User", parsed.username, "is not available");
            } else {
              ws.send(JSON.stringify( {messageType: "checkUsername", username: parsed.username, available: true, messageText: "is available."} ));
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
          let existing;
          const correctUsername = userNameRegex.test(parsed.username);
          if (correctUsername) {
            existing = getUser.get(parsed.username);
          } else {
            ws.send(JSON.stringify( {messageType: "error", messageText: "Username can not contain special charachters"} ));
            return;
          }
          if (existing !== undefined) {
            console.log("Username", parsed.username, "is taken");
            ws.send(JSON.stringify( {messageType: "error", messageText: "username taken"} ));
            return;
          } else {
            const newChallenge = randomBytes(32).toString("hex");
            console.log("The random bytes of data generated is: " + newChallenge.slice(0, 4), "is newChallenge", parsed.username, "is username", parsed.serverPublicKey.slice(0, 4), "is serverPublicKey");
            const createNewUser = db.transaction(() => {
              const newUser = insertUser.run(parsed.username, parsed.serverPublicKey, parsed.userPublicKey, newChallenge);
              console.log("Username", parsed.username, "is written into database");
              const notesID = insertConversationID.run();
              insertConversationParticipants.run(parsed.username, notesID.lastInsertRowid); // My notes
              insertConversationParticipantGroupKey.run(parsed.username, parsed.myGroupKey, notesID.lastInsertRowid);
              return newUser;
            });
            let newUser;
            try {
              newUser = createNewUser();
            } catch {
                ws.send(JSON.stringify( {messageType: "error", messageText: "User creation failed"} ));
                return;
            }
            const databaseUser = getUser.get(parsed.username);
            ws.send(JSON.stringify({ messageType: "auth", messageText: databaseUser.challengeBuffer }));
            console.log("Challenge", databaseUser.challengeBuffer.slice(0, 4), "is sent to", databaseUser.username, "\n");
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
                const updatedChallenge = randomBytes(32).toString('hex');
                updateChallengeBuffer.run(updatedChallenge, authenticatedUser.username);
                console.log("Challenge for ", authenticatedUser.username, " has been updated." );
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
                  console.log("Initial message is sent to", authenticatedUser.username, " as ", authenticatedUser.userRole, "\n");
                  const existingClients = activeClients.get(authenticatedUser.username) || [];
                  existingClients.push(ws);
                  activeClients.set(authenticatedUser.username, existingClients);
                } else if (authenticatedUser.userRole === "user") {
                  const userData = getUserConversationsAndMessages(authenticatedUser.username);
                  const payloadObject = {
                    userRole: "user",
                    messageType: "initialMessage",
                    user: authenticatedUser,
                    conversations: userData
                  }
                  ws.send(JSON.stringify(payloadObject));
                  console.log("All conversations are sent to", authenticatedUser.username, " as ", authenticatedUser.userRole, "\n");
                  const existingClients = activeClients.get(authenticatedUser.username) || [];
                  existingClients.push(ws);
                  activeClients.set(authenticatedUser.username, existingClients);
                }
              } else {
                ws.send(JSON.stringify( {messageType: "noAuth", messageText: "Wrong password"} ));
                console.log("No auth sent to", parsed.username);
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
          if (!requireAuth()) {break;}
          const currentConversationID = getConversationID.get(parsed.conversationID);
          if (currentConversationID !== undefined) {
            const participant = getConversationParticipant.get(currentConversationID.conversationID, authenticatedUser.username);
            if (participant !== undefined) {
              const lastMessage = insertMessage.run(parsed.messageText, parsed.messageType, timeStamp, authenticatedUser.username, currentConversationID.conversationID,);
              const databaseMessage = getMessage.get(authenticatedUser.username, lastMessage.lastInsertRowid);
              const payloadObject = JSON.stringify({
                messageType: "messageConfirm",
                id: lastMessage.lastInsertRowid,
                messageText: databaseMessage.messageText,
                messageTime: timeStamp,
                conversationID: currentConversationID.conversationID,
                sender: authenticatedUser.username
              });
              const participantsOfID = getParticipantsOfID.all(currentConversationID.conversationID);
              participantsOfID.forEach(participant => {
                const connections = activeClients.get(participant.username) || [];
                connections.forEach(clientWS => {
                  if (clientWS.readyState === WebSocket.OPEN) {
                    clientWS.send(payloadObject);
                    console.log("Message confirmation sent to", participant.username);
                  }
                });
              });
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
        break;
        case "delete": {
          if (!requireAuth()) {break;}
          const currentConversationID = getConversationID.get(parsed.conversationID);
          if (currentConversationID !== undefined) {
            const participant = getConversationParticipant.get(currentConversationID.conversationID, authenticatedUser.username);
            if (participant !== undefined) {
              const removedMessage = deleteMessage.run(parsed.id, authenticatedUser.username);
              if (removedMessage.changes === 0) {
                ws.send(JSON.stringify( {messageType: "error", messageText: "Message not found"} ));
                console.log("Message not found");
              } else {
                const payloadObject = JSON.stringify({
                  messageType: "removeMessage",
                  id: parsed.id,
                  conversationID: currentConversationID.conversationID,
                  sender: authenticatedUser.username
                });
                const participantsOfID = getParticipantsOfID.all(currentConversationID.conversationID);
                participantsOfID.forEach(participant => {
                const connections = activeClients.get(participant.username) || [];
                  connections.forEach(clientWS => {
                    if (clientWS.readyState === WebSocket.OPEN) {
                      clientWS.send(payloadObject);
                      console.log("Message confirmation sent to", participant.username);
                    }
                  });
                });
              }
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
        break;
        case "update": {
          if (!requireAuth()) {break;}
          const currentConversationID = getConversationID.get(parsed.conversationID);
          if (currentConversationID !== undefined) {
            const participant = getConversationParticipant.get(currentConversationID.conversationID, authenticatedUser.username);
            if (participant !== undefined) {
              const updatedMessage = updateMessage.run(parsed.messageText, parsed.id, authenticatedUser.username);
              if (updatedMessage.changes === 0) {
                ws.send(JSON.stringify({ messageType: "error", messageText: "Message not found"}));
                break;
              }
              const databaseMessage = getMessage.get(authenticatedUser.username, parsed.id);
              const payloadObject = JSON.stringify({
                messageType: "messageUpdate",
                id: parsed.id,
                messageText: databaseMessage.messageText,
                conversationID: currentConversationID.conversationID,
                sender: authenticatedUser.username });
              const participantsOfID = getParticipantsOfID.all(currentConversationID.conversationID);
              participantsOfID.forEach(participant => {
                const connections = activeClients.get(participant.username) || [];
                connections.forEach(clientWS => {
                  if (clientWS.readyState === WebSocket.OPEN) {
                    clientWS.send(payloadObject);
                    console.log("Message confirmation sent to", participant.username);
                  }
                });
              });
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
        break;
        case "getUserPublicKey": {
          if (!requireAuth()) {break;}
          console.log(authenticatedUser.username, "asked for public key for", parsed.username, "\n");
          const existing = getUser.get(parsed.username);
          if (existing !== undefined) {
            const userPublicKeyResult = getUserPublicKey.get(parsed.username);
            ws.send(JSON.stringify( {messageType: "getUserPublicKey", username: parsed.username, publicKey: userPublicKeyResult.userPublicKey} ));
          } else {
            ws.send(JSON.stringify( {messageType: "error", messageText: `no such user ${parsed.username}`} ));
            console.log(`no such user ${parsed.username}`);
          }
        }
        break;
        case "addGroupConversation": {
          if (!requireAuth()) {break;}
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
              ws.send(JSON.stringify( {messageType: "error", messageText: errorMessage} ));
              allValid = false;
              break;
            }
          }
          if (allValid) {
            if (arrayOfContactUsernames.length === 1) {
              const existingTwoUsersConversationID = getTwoUsersConversationID.get(authenticatedUser.username, arrayOfContactUsernames[0]);
              if (existingTwoUsersConversationID) {
                ws.send(JSON.stringify( {messageType: "error", messageText: "Conversation already exists"}));
                break;
              }
            }
            const createNewConversation = db.transaction(() => {
              const newConversationID = insertConversationID.run();
              insertConversationParticipants.run(authenticatedUser.username, newConversationID.lastInsertRowid);
              insertConversationParticipantGroupKey.run(authenticatedUser.username, parsed.myGroupKey, newConversationID.lastInsertRowid);
              parsed.arrayOfContacts.forEach(contact => {
                insertConversationParticipants.run(contact.username, newConversationID.lastInsertRowid);
                insertConversationParticipantGroupKey.run(contact.username, contact.groupKey, newConversationID.lastInsertRowid);
              });
              return newConversationID;
            });
            let newConversationID;
            try {
              newConversationID = createNewConversation();
            } catch {
              ws.send(JSON.stringify( {messageType: "error", messageText: "Error creating conversation"}));
              return;
            }
            const conversationIDsParticipants = getParticipantsOfID.all(newConversationID.lastInsertRowid);
            const conversationParticipants = [];
            conversationIDsParticipants.forEach(participant => {
              const participantUser = getUser.get(participant.username);
              conversationParticipants.push( {username: participantUser.username, publicKey: participantUser.userPublicKey} );
            });
            conversationIDsParticipants.forEach(participant => {
              const groupKey = getConversationKeyForUser.get(newConversationID.lastInsertRowid, participant.username);
              const conversationObject = JSON.stringify({
                messageType: "userContact",
                conversationID: newConversationID.lastInsertRowid,
                participants: conversationParticipants,
                groupKey: groupKey.groupKey
              });
              const connections = activeClients.get(participant.username) || [];
              connections.forEach(clientWS => {
                if (clientWS.readyState === WebSocket.OPEN) {
                  clientWS.send(conversationObject);
                  console.log("Message confirmation sent to", participant.username);
                }
              });
            });
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
    if(!authenticatedUser) {return;}
    console.log("Client disconnected", authenticatedUser.username);
    const existingConnections = activeClients.get(authenticatedUser.username);
    if (!existingConnections) {return;}
    const newConnections = existingConnections.filter(c => c !== ws);
    if (newConnections.length > 0) {
      activeClients.set(authenticatedUser.username, newConnections);
    } else {
      activeClients.delete(authenticatedUser.username);
    }
  });
  
});
