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
    console.log("received messageData:", messageData);
      switch(messageData.messageType) {
        case "getUserPublicKey": {
          this.callbacks.resolvePublicKeyRequest(messageData);
        }
        break;
        case "checkUsername": {
            this.callbacks.handleUsernameAvailability(messageData);
        }
        break;
        case "error": {
            this.callbacks.showAlert(messageData.messageText);
          }
          break;
          case "noAuth": {
            this.callbacks.showAlert(messageData.messageText);
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
        case "messageConfirm": {
            this.callbacks.addMessageToConversation(messageData);
        }
        break;
        case "userContact": {
            this.callbacks.addConversation(messageData);
        }
        break;
        case "auth": {
            this.username = this.callbacks.getUsername();
            const signatureForServer = await this.callbacks.signData(messageData.messageText);
            const messageJSON = JSON.stringify( {messageType: "auth", messageText: signatureForServer, username: this.username });
            this.callbacks.wsSend(messageJSON);
        }
        break;
      }
  }
}

const sessionVault = new MainVault({
  showAlert: (alert) => chatManager.showAlert(alert),
  resolvePublicKeyRequest: (messageData) => wsManager.resolvePublicKeyRequest(messageData),
  handleInitialCase: (messageData) => chatManager.handleInitialCase(messageData),
  handleMessage: (messageData) => chatManager.handleMessage(messageData),
  addConversation: (messageData) => chatManager.addConversation(messageData),
  addMessageToConversation: (messageData) => chatManager.addMessageToConversation(messageData),
  wsSend: (messageJSON) => wsManager.ws.send(messageJSON),
  signData: (messageData) => sessionCrypto.signData(messageData),
  getUsername: () => storageManager.getUsername(),
  handleNoUserCase: (messageData) =>chatManager.handleNoUserCase(messageData),
  handleUsernameAvailability: (messageData) => chatManager.handleUsernameAvailability(messageData)
});

const storageManager = new StorageManager();

const chatManager = new ChatUI({
  decryptGroupKey: async (keyString) => sessionCrypto.decryptGroupKey(keyString),
  getUserPublicKey: async (username) => wsManager.getUserPublicKey(username),
  getEncryptedGroupKeysForContacts: async (usernamePublicKey) => sessionCrypto.getEncryptedGroupKeysForContacts(usernamePublicKey),
  getUsername: () => storageManager.getUsername(),
  setUsername: (username) => storageManager.setUsername(username),
  decryptMessage: async (key, text) => sessionCrypto.decryptPackage(key, text),
  encryptMessage: (key, text, timestamp) => sessionCrypto.encryptPackage(key, text, timestamp),
  getEncryptedPackages: () => storageManager.getEncryptedPackages(),
  wsSend: (messageJSON) => wsManager.ws.send(messageJSON),
  loadCrypto: (password, stayLoggedIn) => sessionCrypto.load(password, stayLoggedIn),
  startRegistration: (username) => wsManager.registerUser(username),
  getBackup: () => storageManager.getBackupData(),
  setBackup: (file) => storageManager.setBackupData(file)
});

const sessionCrypto = new CryptoVault({
  getCurrentGroup: () => chatManager.getCurrentGroup(),
  getSessionWrappingKey: () => storageManager.getSessionWrappingKey(),
  saveSessionWrappingKey: (key) => storageManager.saveSessionWrappingKey(key),
  getOrCreateWrappingIv: () => storageManager.getOrCreateWrappingIv(),
  getEncryptedSessionKey: () => storageManager.getEncryptedSessionKey(),
  getOrCreateSalt: () => storageManager.getOrCreateSalt(),
  getEncryptedWrappedKey: () => storageManager.getEncryptedWrappedKey(),
  saveEncryptedWrappedKey: (key) => storageManager.saveEncryptedWrappedKey(key),
  getPublicKeyString: () => storageManager.getPublicKeyString(),
  getEncryptedPrivateKey: () => storageManager.getEncryptedPrivateKey(),
  getServerPublicKey: () => storageManager.getServerPublicKey(),
  getEncryptedServerPrivateKey: () => storageManager.getEncryptedServerPrivateKey(),
  saveEncryptedSessionKey: (key) => storageManager.saveEncryptedSessionKey(key),
  saveEncryptedServerPrivateKey: (key) => storageManager.saveEncryptedServerPrivateKey(key),
  savePublicKey: (key) => storageManager.savePublicKey(key),
  saveEncryptedPrivateKey: (key) => storageManager.saveEncryptedPrivateKey(key),
  saveServerPublicKey: (key) => storageManager.saveServerPublicKey(key),
  getOrCreateMessageIv: () => storageManager.getOrCreateMessageIv()
});

const wsManager = new WebSocketManager("ws://localhost:8080", {
  getEncryptedGroupKeysForContacts: async (usernamePublicKey) => sessionCrypto.getEncryptedGroupKeysForContacts(usernamePublicKey),
  getUsername: () => storageManager.getUsername(),
  onMessageReceived: (message) => sessionVault.onMessageReceived(message),
  onClose: () => chatManager.handleCloseCase(),
  setFormVisibility: (event) => chatManager.setFormVisibility(event),
  clearInputs: () => chatManager.clearInputs(),
  handleCloseCase: () => chatManager.handleCloseCase(),
  handleInitialCase: (messageData) => chatManager.handleInitialCase(messageData),
  handleUsernameAvailability: (messageData) => chatManager.handleUsernameAvailability(messageData),
  setUsername: (username) => storageManager.setUsername(username),
  loadCrypto: (userPassword, stayLoggedIn) => sessionCrypto.load(userPassword, stayLoggedIn),
  getPublicKeyString: () => storageManager.getPublicKeyString(),
  serverPublicKey: () => storageManager.getServerPublicKey(),
});

wsManager.connect();
chatManager.scrollToBottom();
