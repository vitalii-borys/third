import { ChatUI } from "/chatUI.js";
import { CryptoVault } from "/cryptoOperations.js";
import { StorageManager } from "/storageManager.js";
import { WebSocketManager } from "/WebSocketManager.js";

class MainVault {
  /* timeOptions = {
    timeZone: 'Europe/Kiev',
    dateStyle: 'short',
    timeStyle: 'short',
  }; */
  currentMessageId = 0;
  username;

  constructor(callbacks) {
    this.callbacks = callbacks;
  }

  async onMessageReceived(message) {
    const messageData = JSON.parse(message.data);
      switch(messageData.messageType) {
        case "checkUsername": {
            this.callbacks.handleUsernameAvailability(messageData);
        }
        break;
        case "error": {
            console.log(messageData);
        }
        break;
        case "noAuth": {
            console.log(messageData);
        }
        break;
        case "noUser": {
            this.callbacks.handleNoUserCase(messageData);
        }
        break;
        case "initialMessage": {
            localStorage.setItem("username", this.username);
            this.callbacks.handleInitialCase(messageData);
        }
        break;
        case "userContact": {
            this.callbacks.addContact(messageData);
        }
        break;
        case "auth": {
            this.username = this.callbacks.setUsername();
            const signatureForServer = await this.callbacks.signData(messageData.messageText);
            const messageJSON = JSON.stringify( {messageType: "auth", messageText: signatureForServer, username: this.username });
            this.callbacks.wsSend(messageJSON);
        }
        break;
      }
  }

  async handleMessage(message) {
    try {
      let decryptedData = await sessionCrypto.decryptPackage(message.messageText);
      chatManager.handleMessage(decryptedData);
      this.currentMessageId = message.id;
      console.log("this.currentMessageId", this.currentMessageId);
    } catch (e) {
      console.log("Server message decryption failed.", e);
    }
  }
}

const storageManager = new StorageManager();
const sessionCrypto = new CryptoVault(storageManager);
const sessionVault = new MainVault({
  handleInitialCase: (messageData) => chatManager.handleInitialCase(messageData),
  addContact: (messageData) => chatManager.addContact(messageData),
  wsSend: (messageJSON) => wsManager.ws.send(messageJSON),
  signData: (messageData) => sessionCrypto.signData(messageData),
  setUsername: (username) => chatManager.setUsername(username),
  handleNoUserCase: (messageData) =>chatManager.handleNoUserCase(messageData),
  handleUsernameAvailability: (messageData) => chatManager.handleUsernameAvailability(messageData)
});
const wsManager = new WebSocketManager("ws://localhost:8080", {
  onMessageReceived: (message) => sessionVault.onMessageReceived(message),
  onClose: () => chatManager.handleCloseCase(),
  setFormVisibility: (event) => chatManager.setFormVisibility(event),
  clearInputs: () => chatManager.clearInputs(),
  handleCloseCase: () => chatManager.handleCloseCase(),
  handleInitialCase: (messageData) => chatManager.handleInitialCase(messageData),
  handleUsernameAvailability: (messageData) => chatManager.handleUsernameAvailability(messageData),
  handleNoUserCase: (messageData) => chatManager.handleNoUserCase(messageData),
  setUsername: (username) => chatManager.setUsername(username),
  loadCrypto: (userPassword, stayLoggedIn) => sessionCrypto.load(userPassword, stayLoggedIn),
  getPublicKey: () => storageManager.getPublicKey(),
  serverPublicKey: () => storageManager.getServerPublicKey(),
});

const chatManager = new ChatUI({
  decryptMessage: (text) => sessionCrypto.decryptPackage(text),
  encryptMessage: (text) => sessionCrypto.encryptPackage(text),
  getEncryptedPackages: () => storageManager.getEncryptedPackages(),
  wsSend: (messageJSON) => wsManager.ws.send(messageJSON),
  loadCrypto: (password, stayLoggedIn) => sessionCrypto.load(password, stayLoggedIn),
  startRegistration: (username) => wsManager.registerUser(username),
  getBackup: () => storageManager.getBackupData(),
  setBackup: (file) => storageManager.setBackupData(file)
});
wsManager.connect();
chatManager.scrollToBottom();