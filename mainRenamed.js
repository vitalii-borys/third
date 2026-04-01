const timestampLength = 8;
const saltLength = 16;
const ivLength = 12;

const userInput = document.getElementById('user_input');
const userMessages = document.getElementById('userMessages');
const saveButton = document.getElementById('saveButton');
const backupButton = document.getElementById('backupButton');
const uploadBackupButton = document.getElementById('uploadBackupButton');
const fileUpload = document.getElementById('fileUpload');
const contactDiv = document.getElementById("contactDiv");
const contactControls = document.getElementById("contactControls");
const contactButton = document.getElementById('contactButton');
const logInForm = document.getElementById('logInForm');
const registrationForm = document.getElementById('registrationForm');
const loginUsernameInput = document.getElementById('loginUsernameInput');
const loginPasswordInput = document.getElementById('loginPasswordInput');
const registerUsernameInput = document.getElementById('registerUsernameInput');
const loginButton = document.getElementById('loginButton');
const registrationSignupButton = document.getElementById('registrationSignupButton');
const loginUsernameInputLabel = document.getElementById('loginUsernameInputLabel');
const loginPasswordInputLabel = document.getElementById('loginPasswordInputLabel');
const registerPasswordInput = document.getElementById('registerPasswordInput');
const registerPasswordInputConfirm = document.getElementById('registerPasswordInputConfirm');
const registerUsernameInputLabel = document.getElementById('registerUsernameInputLabel');
const registerPasswordInputLabel = document.getElementById('registerPasswordInputLabel');
const registerPasswordInputConfirmLabel = document.getElementById('registerPasswordInputConfirmLabel');
const logoutButton = document.getElementById('logout');
const stayLoggedIn = document.getElementById('stayLoggedIn');
const welcome = document.getElementById('welcome');

userInput.focus();
userInput.addEventListener("input", function() {
  this.style.height = "auto";
  this.style.height = (this.scrollHeight) + "px";
});

function scrollToBottom() {
  requestAnimationFrame(() => {
    userMessages.scrollTop = userMessages.scrollHeight;
  });
}

class CryptoVault {
  #wrappingIv;
  #messageIv;
  #salt;
  #sessionKey;
  #localStorageAvailable;
  serverPublicKey;
  clientPublicKey;
  #serverPrivateKey;
  #clientPrivateKey;
  #wrappingKey;
  username;
  usernameAvailable = null;
  passwordCorrect = null;
  #role;
  #encryptedPackages;
  timeOptions = {
    timeZone: 'Europe/Kiev',
    dateStyle: 'short',
    timeStyle: 'short',
  };
  days = ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
  months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  ws = null;
  websocketServerLocation = "ws://localhost:8080"; // will need to wss for deploying
  maxReconnectInterval = 60000;
  reconnectionAttempts = 0;
  forceClose = false;
  currentMessageId = 0;

  constructor() {
    this.#localStorageAvailable = CryptoVault.storageAvailable("localStorage");
  }

  disconnect() {
    this.forceClose = true;
    if (this.ws) {
      this.ws.close();
    }
  }

  async handleMessage(message) {
    try {
      let decryptedData = await this.decryptPackage(message.messageText);
      this.currentMessageId = message.id;
      console.log("this.currentMessageId", this.currentMessageId);
      const messageDiv = this.createMessageElement(decryptedData.message, decryptedData.receivedTimestamp, message.id);
      userMessages.append(messageDiv);
    } catch (e) {
      console.log("Server message decryption failed.", e);
    }
  }

  createMessageElement = (message, timestamp, id) => {
    const messageDiv = document.createElement('div');
    const messageTime = new Date(Number(timestamp));
    const formatted = `${String(messageTime.getHours()).padStart(2, 0)}:${String(messageTime.getMinutes()).padStart(2, 0)}`;
    messageDiv.classList = "message";
    const dayName = this.days[messageTime.getDay()];
    let messageTextEl = document.createElement('div');
    let messageDayEl = document.createElement('div');
    let messageTimeEl = document.createElement('div');
    messageTextEl.classList = "messageTextEl";
    messageDayEl.classList = "messageDayEl";
    messageTimeEl.classList = "messageTimeEl";
    messageTextEl.textContent = message;
    messageDayEl.textContent = `${dayName}`;
    messageTimeEl.textContent = formatted;
    messageDiv.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      this.createContextMenu(e.pageX, e.pageY, id, messageDiv);
    });
    messageDiv.append(messageTextEl, messageDayEl, messageTimeEl);
    return messageDiv;
  }

  createContextMenu (x, y, messageId, divToRemove) {
    const menu = document.getElementsByClassName('contextMenu');
    if (menu[0] !== undefined) {
      menu[0].remove();
    }
    const contextMenu = document.createElement('div');
    const removeButton = document.createElement('div');
    const updateButton = document.createElement('div');
    contextMenu.classList = 'contextMenu';
    contextMenu.style.position = 'absolute';
    contextMenu.style.left = `${x + 5}px`;
    contextMenu.style.top = `${y + 5}px`;
    updateButton.textContent = 'Edit';
    updateButton.style.position = 'relative';
    updateButton.style.backgroundColor = 'white';
    removeButton.textContent = 'Delete';
    removeButton.style.position = 'relative';
    removeButton.style.backgroundColor = 'white';
    contextMenu.append(updateButton, removeButton);
    removeButton.addEventListener('mouseenter', () => {
      removeButton.style.background = "lightpink";
    });
    removeButton.addEventListener('mouseleave', () => {
      removeButton.style.background = "white";
    });
    updateButton.addEventListener('mouseenter', () => {
      updateButton.style.background = "lightblue";
    });
    updateButton.addEventListener('mouseleave', () => {
      updateButton.style.background = "white";
    });
    removeButton.addEventListener('click', () => {
      const messageJSON = JSON.stringify({ id: messageId, username: this.username, messageType: "delete" });
      console.log(messageJSON);
      this.ws.send(messageJSON);
      contextMenu.remove();
      divToRemove.remove();
    });
    updateButton.addEventListener('click', () => {
      const inputElement = document.createElement('input');
      inputElement.type = 'text';
      inputElement.style.all = 'inherit';
      inputElement.style.backgroundColor = 'white';
      inputElement.value = divToRemove.children[0].innerText;
      const unUpdatedMessage = divToRemove.children[0]
      divToRemove.children[0].replaceWith(inputElement);
      inputElement.focus();

      setTimeout(() => {
        document.addEventListener('click', () => {
          inputElement.replaceWith(unUpdatedMessage);
        }, { once: true });
      }, 5);

      inputElement.addEventListener('keydown', async (e) => {
        if (e.key === 'Escape') {
          inputElement.replaceWith(unUpdatedMessage);
        }
        if (e.key === 'Enter') {
          const decryptedMessageToEdit = await this.decryptPackage(this.#encryptedPackages.messages[messageId].text);
          console.log(decryptedMessageToEdit);
          const messageToEditTimestamp = decryptedMessageToEdit.receivedTimestamp;
          console.log(messageToEditTimestamp);
          const updatedDiv = document.createElement("div");
          updatedDiv.classList = "messageTextEl";
          let newMessage;
          try {
            newMessage = await this.encryptPackage(inputElement.value, messageToEditTimestamp);
          } catch (e) {
            console.log("Error", e);
          }
          updatedDiv.textContent = inputElement.value;
          inputElement.replaceWith(updatedDiv);
          const messageJSON = JSON.stringify({ id: messageId, "messageText": newMessage, username: this.username, messageType: "update" });
          console.log(messageJSON);
          this.ws.send(messageJSON);
        }
      });
      contextMenu.remove();
    });
    const closeMenu = (e) => {
      if (!removeButton.contains(e.target)) {
        contextMenu.remove();
        document.removeEventListener('click', closeMenu);
      }
    }
    setTimeout(() => {
      document.addEventListener('click', closeMenu);
    }, 5);
    document.body.append(contextMenu);
    return removeButton;
  }

  async registerUser(username) { 
    const exportedPublicKey = await crypto.subtle.exportKey("spki", this.serverPublicKey);
    const publicKeyBuffer = new Uint8Array(exportedPublicKey).toBase64();
    const messageJSON = JSON.stringify( {messageType: "register", username: username, publicKey: publicKeyBuffer });
    this.ws.send(messageJSON);
    console.log(messageJSON, "sent to server");
  }

  connect() {
    this.forceClose = false;
    this.ws = new WebSocket(this.websocketServerLocation);
    this.ws.onopen = async () => {
      console.log("Connected to server");
      connectionTitle.style.display = "none";
      const localUsername = localStorage.getItem("username");
      if (localUsername !== null) {
        logInForm.style.display = "flex";
        loginUsernameInput.value = localUsername;
      } else {
        registrationForm.style.display = "flex";
        registerUsernameInput.focus();
      }
      const keyString = sessionStorage.getItem("wrappingKey");
      if (keyString !== null) {
        await this.load();
        this.username = localStorage.getItem("username");
        console.log(this.username, "assigned from local storage")
        try {
          if (this.username !== undefined) {
            const messageJSON = JSON.stringify( {messageType: "challenge", username: this.username} );
            this.ws.send(messageJSON);
            registrationForm.style.display = "none";
            backupButton.disabled = false;
            saveButton.disabled = false;
          }
        } catch(err) {
          console.log(err);
        }
        setTimeout(() => {
          loginUsernameInput.value = "";
          loginPasswordInput.value = "";
          registerUsernameInput.value = "";
          registerPasswordInput.value = "";
          registerPasswordInputConfirm.value = "";
        }, 500);
      }
      this.reconnectionAttempts = 0;
    };
      
    // have to implement client send message logic to fail sending message when server is down by checking ws.readyState
    this.ws.onmessage = async(message) => {
      const messageData = JSON.parse(message.data);
      switch(messageData.messageType) {
        case "checkUsername": {
          if (messageData.messageText !== undefined) {
            this.usernameAvailable = null;
            registerUsernameInputLabel.textContent = `Username ${messageData.username} ${messageData.messageText}`;
            registerUsernameInputLabel.style.color = 'pink';
          } else {
            if (!messageData.available) {
              this.usernameAvailable = false;
              registerUsernameInputLabel.textContent = `Username ${messageData.username} is not available`;
              registerUsernameInputLabel.style.color = 'pink';
            } else {
              this.usernameAvailable = true;
              registerUsernameInputLabel.textContent = `Username ${messageData.username} is available`;
              registerUsernameInputLabel.style.color = 'lightgreen';
            }
            console.log(messageData);
          }
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
          let alertDiv = document.getElementById('alertDiv');
          if (alertDiv === null) {
            const alertDiv = document.createElement('div');
            alertDiv.textContent = messageData.messageText;
            alertDiv.id = "alertDiv";
            contactControls.appendChild(alertDiv);
          } else {
            const alertDiv = document.getElementById('alertDiv');
            alertDiv.textContent = messageData.messageText;
          }
        }
        break;
        case "initialMessage": {
          registrationForm.style.display = "none";
          logInForm.style.display = "none";
          chatDiv.style.display = "flex";
          backupControls.style.display = "flex";
          contactContainer.style.display = "flex";

          if (messageData.userRole === "admin") {
            this.#role = "admin";
            console.log(this.#role, "is yor role");            
            const adminbutton = document.getElementById("adminButton");
            adminbutton.style.display = "flex";
            const adminTable = document.getElementById("adminTable");
            const adminTableBody = document.getElementById("adminTableBody");
            adminbutton.addEventListener('click', () => {
              if (adminbutton.textContent === "Show database") {
                adminbutton.textContent = "Hide database";
                adminTable.style.display = "block";
              } else {
                adminTableBody.innerHTML = ""; // will need to change to textContent
                adminbutton.textContent = "Show database";
                adminTable.style.display = "none";
              }
              if (this.#role === "admin") {
                adminTableBody.innerHTML = "";
                let row;
                messageData.users.forEach(user => {
                  messageData.allMessages.forEach(message => {
                    if (message.username === user.username) {
                      console.log(message.username);
                      const timestamp = new Date(message.messageTime);
                      const formattedTimestamp = `${String(timestamp.getDate())} ${String(this.months[timestamp.getMonth()])} ${String(timestamp.getHours()).padStart(2, 0)}:${String(timestamp.getMinutes()).padStart(2, 0)}`
                      row =  `<tr><th>${user.username}</th><td>${user.userRole}</td><td>${formattedTimestamp}</td></tr>`
                    }
                  });
                  adminTableBody.innerHTML += row;
                });
              } else if (this.#role === "user") {
                console.log("You are user");
              } else {
                console.log("Role is not set");
              }
            });
          } else if (messageData.userRole === "user") {
            console.log(messageData);
            this.#role = "user";
            console.log(this.#role, "is yor role");
          }
          userMessages.innerHTML = "";
          /* for (const msg of messageData.messages) {
            await this.handleMessage(msg);
          } */
          contactDiv.innerHTML = "";
          const userContacts = messageData.conversations;
          userContacts.forEach(contact => {
            const newContactDiv = document.createElement('div');
            newContactDiv.classList = "newContactDiv";
            if (contact.contactusername === this.username) {
              newContactDiv.textContent = "My notes";
            } else {
              newContactDiv.textContent = contact.contactusername;
            }
            contactDiv.appendChild(newContactDiv);
          });
          scrollToBottom();
        }
        break;
        case "userContact": {
          console.log(messageData);
          const newContactDiv = document.createElement('div');
          newContactDiv.classList = "newContactDiv";
          newContactDiv.textContent = messageData.username;
          contactDiv.appendChild(newContactDiv);
        }
        break;
        case "auth": {
          const signatureForServer = await this.signData(messageData.messageText);
          const messageJSON = JSON.stringify( {messageType: "auth", messageText: signatureForServer, "username": this.username });
          this.ws.send(messageJSON);
          //console.log(messageJSON, "sent");
        }
        break;
      }
    }

    this.ws.onclose = () => {
      if (this.forceClose) {
        console.log("Disconnected manually. Stopping reconnection.");
        return;
      }

      contactContainer.style.display = "none";
      backupControls.style.display = "none";
      chatDiv.style.display = "none";
      logInForm.style.display = "none";
      registrationForm.style.display = "none";
      connectionTitle.style.display = "flex";

      this.reconnectionAttempts++;
      const baseWait = Math.min(this.maxReconnectInterval, 3000 * Math.pow(2, this.reconnectionAttempts - 1));
      const jitter = Math.random() * (baseWait * 0.25);
      const reconnectInterval = baseWait + jitter;
      console.log("Connection closed. Reconnecting after", reconnectInterval, "ms", this.ws.readyState);
      setTimeout(() => {
        if (!this.forceClose) {
          this.connect();
        }
      }, reconnectInterval);
      this.ws.onclose = null;
    }
    
    this.ws.onerror = () => {
      console.log("Error. Ready state:", this.ws.readyState);
      this.ws.close();
      this.ws.onerror = null;
    }
  }

  async load(userPassword, username) {
    if (userPassword === undefined && username === undefined) {
      this.username = localStorage.getItem("username");
      this.#sessionKey = await this.#getKey();
      await this.encryptAndStorePrivatePublicKeys();
    } else {
      this.username = username;
      this.#sessionKey = await this.#getKey(userPassword);
      await this.encryptAndStorePrivatePublicKeys();
    }
    return this;
  }

  getBackupData () {
    this.#initializeStorage();
    const backupJSON = {
      "encryptedPackages": this.#encryptedPackages,
      "encryptedWrappedKey": localStorage.getItem("encryptedWrappedKey"),
      "messageIV": localStorage.getItem("messageIv"),
      "encryptedSessionKey": localStorage.getItem("encryptedSessionKey"),
      "publicKey": localStorage.getItem("publicKey"),
      "encryptedPrivateKey": localStorage.getItem("encryptedPrivateKey"),
      "salt": localStorage.getItem("salt"),
      "wrappingIv": localStorage.getItem("wrappingIv")
    };
    return backupJSON;
  }

  async signData(data) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    let signature = await window.crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      this.#serverPrivateKey,
      encodedData
    );
    signature = new Uint8Array(signature).toBase64();
    return signature;
  }

  async encryptStoreAndSend(userInput) {
    if (userInput === "") {
      return;
    }
    const packageData = await this.encryptPackage(userInput);
    this.#encryptedPackages.messages.push({id: this.#encryptedPackages.messages[this.#encryptedPackages.messages.length - 1].id + 1, text: packageData})
    localStorage.setItem("encryptedPackages", JSON.stringify({messages: this.#encryptedPackages.messages}));
    const messageTime = new Date();
    this.currentMessageId++;
    const userMessage = this.createMessageElement(userInput, messageTime, this.currentMessageId);
    const messageJSON = JSON.stringify( {
      id: this.currentMessageId,
      messageText: packageData,
      messageType: "message",
      username: this.username,
    });
    this.ws.send(messageJSON);
    console.log(messageJSON);
    userMessages.append(userMessage);
    scrollToBottom();
  }

  #bigintToUint8Buffer (bigInt) {
    let dataView = new DataView(new ArrayBuffer(8), 0);
    dataView.setBigUint64(0, bigInt);
    let uint8Array = new Uint8Array(dataView.buffer);
    return uint8Array;
  }

  #uint8ArrayToBigint (bigIntBuffer) {
    let dataView = new DataView(bigIntBuffer.buffer, 0);
    let myBigInt = dataView.getBigUint64(0);
    return myBigInt;
  }
  
  async encryptPackage(data, timestamp) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    let additionalData;
    if (timestamp !== undefined) {
      additionalData = this.#bigintToUint8Buffer(timestamp);
    } else {
      additionalData = this.#bigintToUint8Buffer(BigInt(Date.now()));
    }
    this.#incrementIV(this.#messageIv);
    localStorage.setItem("messageIv", this.#messageIv.toBase64());
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: this.#messageIv,
        additionalData: additionalData
      },
      this.#sessionKey,
      encodedData,
    );
    const ciphertextArray = new Uint8Array(ciphertext);
    const packageData = new Uint8Array(timestampLength + ivLength + ciphertextArray.length);
    packageData.set(additionalData, 0);
    packageData.set(this.#messageIv, timestampLength);
    packageData.set(ciphertextArray, timestampLength + ivLength);
    const package64 = packageData.toBase64();
    console.log("package64 :", typeof package64, package64);
    return package64;
  }

  async decryptPackage(packageData) {
    const packageToBytes = Uint8Array.fromBase64(packageData);
    const receivedTimestampArray = packageToBytes.slice(0, timestampLength);
    const receivedTimestamp = this.#uint8ArrayToBigint(receivedTimestampArray);
    const receivedMessageIvArray = packageToBytes.slice(timestampLength, timestampLength + ivLength);
    const receivedCiphertextArray = packageToBytes.slice(timestampLength + ivLength);
    try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: receivedMessageIvArray,
        additionalData: receivedTimestampArray
      },
      this.#sessionKey,
      receivedCiphertextArray,
      );
      const message = new TextDecoder().decode(decryptedBuffer);
      const decryptedData = {
        message,
        receivedTimestamp
      };
      return decryptedData;
    } catch (e) {
      console.log("Decryption failed with error: ", e);
      return;
    }
  }

  async getMasterKey(encodedPassword) {
    const masterKey = await window.crypto.subtle.importKey("raw", encodedPassword, "PBKDF2", false, ["deriveKey"]);
    return masterKey;
  }

  async deriveWrappingKey(masterKey, salt) {
    if (masterKey === undefined && salt === undefined) {
      const importKeyBuffer = Uint8Array.fromBase64(sessionStorage.getItem("wrappingKey"));
      const decryptedKey = await window.crypto.subtle.importKey(
        "raw",
        importKeyBuffer,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"],
      );
      return decryptedKey;
    } else {
      const wrappingKey = await window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 700000,
          hash: "SHA-256"
        },
        masterKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
      this.#wrappingKey = wrappingKey;
      const exportedWrappingKey = await window.crypto.subtle.exportKey("raw", wrappingKey);
      const wrappingKeyBuffer = new Uint8Array(exportedWrappingKey).toBase64();
      console.log(stayLoggedIn.checked);
      if (stayLoggedIn.checked) {
        sessionStorage.setItem("wrappingKey", wrappingKeyBuffer);
      }
      console.log("Session key is written to session storage");
      return wrappingKey;
    }
  }
  
  async #getKey(userPassword) {
    this.#initializeStorage();
    var encodedPassword = new TextEncoder().encode(userPassword);
    userPassword = "";
    const masterKey = await this.getMasterKey(encodedPassword);
    encodedPassword = null;
    const sessionKeyFromSessionStorage = sessionStorage.getItem("wrappingKey");
    let wrappingKey;
    if (sessionKeyFromSessionStorage !== null) {
      wrappingKey = await this.deriveWrappingKey();
    } else {
      wrappingKey = await this.deriveWrappingKey(masterKey, this.#salt);
    }
    this.#wrappingKey = wrappingKey;
    //console.log("Wrapping key is: ", wrappingKey);
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("encryptedWrappedKey") !== null) {
        try {
          const decryptBuffer = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: this.#wrappingIv,
            },
            wrappingKey,
            Uint8Array.fromBase64(localStorage.getItem("encryptedWrappedKey")),
          );
          const decryptedKey = await window.crypto.subtle.importKey(
            "raw",
            decryptBuffer,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"],
          );
          return decryptedKey;
        } catch (e) {
          console.log("Decryption failed with error: ", e);
          throw new Error("Wrong password");
        }
      } else {
        this.#incrementIV(this.#wrappingIv);
        localStorage.setItem("wrappingIv", this.#wrappingIv.toBase64());
        console.log(typeof this.#wrappingIv, "WrappingIv ", this.#wrappingIv, " stored in local storage: ", this.#wrappingIv.toString());
        const generatedKey = await window.crypto.subtle.generateKey(
          {
            name: "AES-GCM",
            length: 256,
          },
          true,
          ["encrypt", "decrypt"],
        );
        console.log("No key in local storage so newely genegated random key is: ", typeof generatedKey, generatedKey);
        const exportedKey = await window.crypto.subtle.exportKey("raw", generatedKey);
        console.log(typeof exportedKey, "Exported Key is: ", exportedKey);
        const encryptedWrappingKey = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: this.#wrappingIv,
          },
          wrappingKey,
          new Uint8Array(exportedKey),
        );
        const encryptedWrappedKey = new Uint8Array(encryptedWrappingKey).toBase64();
        console.log(typeof encryptedWrappedKey, "Exported wrapped key is: ", encryptedWrappedKey, " written to local storage.");
        localStorage.setItem("encryptedWrappedKey", encryptedWrappedKey);
        return generatedKey;
      }
    } else {
      console.log("Too bad, no local storage for us.");
    }
  }

  async #generateKeyPair(keyPairType) {
    let keyPair = null;
    if (keyPairType === "server") {
      keyPair = window.crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"]
      )
    } else if (keyPairType === "client") {      
      keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
      );
    }
    return keyPair;
  }

  async encryptAndStorePrivatePublicKeys() {
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("encryptedSessionKey") !== null
      && localStorage.getItem("encryptedPrivateKey") !== null && localStorage.getItem("publicKey") !== null
      && localStorage.getItem("encryptedServerPrivateKey") !== null && localStorage.getItem("serverPublicKey") !== null) {

        const publicKeyBuffer = Uint8Array.fromBase64(localStorage.getItem("publicKey"));
        const publicKey = await crypto.subtle.importKey(
          "spki",
          publicKeyBuffer,
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        );
        this.clientPublicKey = publicKey;
        
        const privateKeyBuffer = Uint8Array.fromBase64(localStorage.getItem("encryptedPrivateKey"));
        let decryptedPrivateKey;
        try {
          decryptedPrivateKey = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: this.#wrappingIv
            },
            this.#wrappingKey,
            privateKeyBuffer
          );
        } catch (e) {
          console.log("Decryption failed with error: ", e);
          throw new Error("Wrong password");
        }
        const privateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            decryptedPrivateKey,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"],
          );
        this.#clientPrivateKey = privateKey;
        
        const serverPublicKeyBuffer = Uint8Array.fromBase64(localStorage.getItem("serverPublicKey"));
        const serverPublicKey = await crypto.subtle.importKey(
          "spki",
          serverPublicKeyBuffer,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          true,
          ["verify"]
        );
        this.serverPublicKey = serverPublicKey;
        
        const serverPrivateKeyBuffer = Uint8Array.fromBase64(localStorage.getItem("encryptedServerPrivateKey"));
        let decryptedServerPrivateKey;
        try {
          decryptedServerPrivateKey = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: this.#wrappingIv
            },
            this.#wrappingKey,
            serverPrivateKeyBuffer
          );
        } catch (e) {
          console.log("Decryption failed with error: ", e);
          throw new Error("Wrong password");
        }
        const serverPrivateKey = await window.crypto.subtle.importKey(
            "pkcs8",
            decryptedServerPrivateKey,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            true,
            ["sign"],
          );
        this.#serverPrivateKey = serverPrivateKey;

      } else {
        const clientKeyPair = await this.#generateKeyPair("client");
        const serverKeyPair = await this.#generateKeyPair("server");
        
        const clientPublicKey = clientKeyPair.publicKey;
        const clientPrivateKey = clientKeyPair.privateKey;
        this.clientPublicKey = clientPublicKey;
        this.#clientPrivateKey = clientPrivateKey;
        console.log("No key pair in local storage so newely generated keys are: ", clientPublicKey, clientPrivateKey);
        
        const exportedPublicKey = await crypto.subtle.exportKey("spki", clientPublicKey);
        localStorage.setItem("publicKey", new Uint8Array(exportedPublicKey).toBase64());
        
        const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#clientPrivateKey);
        const privateKeyBuffer = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: this.#wrappingIv
          },
          this.#wrappingKey,
          exportedPrivateKey
        );
        const privateKeyBufferString = new Uint8Array(privateKeyBuffer).toBase64();
        localStorage.setItem("encryptedPrivateKey", privateKeyBufferString);
        
        const exportedSessionKey = await crypto.subtle.exportKey("raw", this.#sessionKey);
        console.log(exportedSessionKey);
        const sessionKeyBuffer = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: this.#wrappingIv
          },
          this.#sessionKey,
          exportedSessionKey
        );
        const sessionKeyBufferString = new Uint8Array(sessionKeyBuffer).toBase64();
        localStorage.setItem("encryptedSessionKey", sessionKeyBufferString);
        
        const serverPublicKey = serverKeyPair.publicKey;
        const serverPrivateKey = serverKeyPair.privateKey;
        this.serverPublicKey = serverPublicKey;
        this.#serverPrivateKey = serverPrivateKey;
        console.log("No key pair in local storage so newely generated server keys are: ", serverPublicKey, serverPrivateKey);

        const exportedServerPublicKey = await crypto.subtle.exportKey("spki", serverPublicKey);
        localStorage.setItem("serverPublicKey", new Uint8Array(exportedServerPublicKey).toBase64());
        
        const exportedSeverPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#serverPrivateKey);
        const serverPrivateKeyBuffer = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: this.#wrappingIv
          },
          this.#wrappingKey,
          exportedSeverPrivateKey
        );
        const serverPrivateKeyBufferString = new Uint8Array(serverPrivateKeyBuffer).toBase64();
        localStorage.setItem("encryptedServerPrivateKey", serverPrivateKeyBufferString);
      }
    }
  }

  #initializeStorage() {
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("encryptedPackages") !== null) {
        this.#encryptedPackages = JSON.parse(localStorage.getItem("encryptedPackages"));
        //console.log("Encrypted packages from local storage: ", this.#encryptedPackages);
      } else {
        localStorage.setItem("encryptedPackages", JSON.stringify({messages: [{id: 0, text: ""}]}));
        this.#encryptedPackages = JSON.parse(localStorage.getItem("encryptedPackages"));
        console.log("No encrypted packages in local storage: ", this.#encryptedPackages, " created.");
      }
      if (localStorage.getItem("wrappingIv") !== null) {
        this.#wrappingIv = Uint8Array.fromBase64(localStorage.getItem("wrappingIv"));
        //console.log("WrappingIv from local storage is: ", this.#wrappingIv.toString());
      } else {
        this.#wrappingIv = crypto.getRandomValues(new Uint8Array(ivLength));
        localStorage.setItem("wrappingIv", this.#wrappingIv.toBase64());
        console.log(typeof this.#wrappingIv, "WrappingIv ", this.#wrappingIv, " stored in local storage: ", this.#wrappingIv.toString());
      }
      if (localStorage.getItem("messageIv") !== null) {
        this.#messageIv = Uint8Array.fromBase64(localStorage.getItem("messageIv"));
        //console.log("MessageIv from local storage: ", this.#messageIv.toString());
      } else {
        console.log("No messageIv in local storage");
        const messageIvStart = crypto.getRandomValues(new Uint8Array(ivLength - 4));
        const messageIvEnd = new Uint8Array(4).fill(0);
        this.#messageIv = new Uint8Array(ivLength);
        this.#messageIv.set(messageIvStart, 0);
        this.#messageIv.set(messageIvEnd, messageIvStart.length);
        localStorage.setItem("messageIv", this.#messageIv.toBase64());
        console.log("messageIv ", this.#messageIv, " stored in local storage: ", this.#messageIv.toString());
      }
      if (localStorage.getItem("salt") !== null) {
        this.#salt = Uint8Array.fromBase64(localStorage.getItem("salt"));
        //console.log("Salt from local storage: ", this.#salt.toString());
      } else {
        this.#salt = crypto.getRandomValues(new Uint8Array(saltLength));
        console.log("Salt :", this.#salt);
        var saltString = this.#salt.toBase64();
        localStorage.setItem("salt", saltString);
        console.log("Salt :", saltString, " stored in local storage.");
      }
    }
  }
  
  static storageAvailable(type) {
    let storage;
    try {
      storage = window[type];
      const x = "__storage_test__";
      storage.setItem(x, x);
      storage.removeItem(x);
      return true;
    } catch (e) {
      return (
        e instanceof DOMException &&
        e.name === "QuotaExceededError" &&
        storage &&
        storage.length !== 0
      );
    }
  }

  #incrementIV(buffer) {
    for (let i = buffer.length - 1; i >= 0; i--) {
      buffer[i]= (buffer[i] + 1) % 256;
      if (buffer[i] !== 0) {
        break;
      }
    }
  }
}

const connectionTitle = document.createElement("h1");
connectionTitle.id = "connectionTitle";
connectionTitle.textContent = "Connecting to server...";
document.body.appendChild(connectionTitle);

let sessionVault = new CryptoVault();
sessionVault.connect();

registerPasswordInputConfirm.addEventListener('keypress', (event) => {
  if (event.key === 'Enter') {
    registrationSignupButton.click();
  }
});

let timeoutID;
registerPasswordInputConfirm.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (registerPasswordInputConfirm.value.length === 0) {
      sessionVault.passwordCorrect = null;
      registerPasswordInputConfirmLabel.textContent = 'Write password';
      registerPasswordInputConfirmLabel.style.color = 'black';
      registerPasswordInputConfirm.style.backgroundColor = 'white';
    } else if (registerPasswordInputConfirm.value !== registerPasswordInput.value) {
      sessionVault.passwordCorrect = false;
      registerPasswordInputConfirmLabel.textContent = "Passwords don't match";
      registerPasswordInputConfirm.style.backgroundColor = 'pink';
    } else {
      sessionVault.passwordCorrect = true;
      registerPasswordInputConfirmLabel.textContent = 'Password confirmed';
      registerPasswordInputConfirm.style.backgroundColor = 'lightgreen';
    }
  }, 500);
});

registerPasswordInput.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (registerPasswordInput.value.length === 0) {
      registerPasswordInputLabel.textContent = 'Write password';
      registerPasswordInputLabel.style.color = 'black';
      registerPasswordInput.style.backgroundColor = 'white';
    } else if (registerPasswordInput.value.length < 6) {
      registerPasswordInputLabel.textContent = '6 charachters minimum';
      registerPasswordInput.style.backgroundColor = 'pink';
    } else {
      registerPasswordInputLabel.textContent = 'Password is good';
      registerPasswordInput.style.backgroundColor = 'lightgreen';
    }
  }, 500);
});

registerUsernameInput.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (registerUsernameInput.value.length === 0) {
      registerUsernameInputLabel.textContent = 'Write username';
      registerUsernameInputLabel.style.color = 'black';
      registerUsernameInput.style.backgroundColor = 'white';
      return;
    } else if (registerUsernameInput.value.length < 3) {
      registerUsernameInput.style.backgroundColor = 'pink';
    } else {
      registerUsernameInput.style.backgroundColor = 'white';
    }
    const messageJSON = JSON.stringify({ messageType: "checkUsername", "username": registerUsernameInput.value });
    sessionVault.ws.send(messageJSON);
    console.log(messageJSON, "sent to server");
  }, 100);
});

loginPasswordInput.addEventListener('keypress', (event) => {
  if (loginUsernameInput.value.length < 3 && event.key === "Enter") {
    loginButton.click();
  }
});

loginPasswordInput.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (loginPasswordInput.value.length === 0) {
      loginPasswordInputLabel.textContent = 'Password';
      loginPasswordInputLabel.style.color = 'black';
      loginPasswordInput.style.backgroundColor = 'white';
    } else if (loginPasswordInput.value.length < 6) {
      loginPasswordInput.style.backgroundColor = 'pink';
    } else {
      loginPasswordInput.style.backgroundColor = 'white';
    }
  }, 100);
});

loginUsernameInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
  }
});

loginUsernameInput.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (loginUsernameInput.value.length === 0) {
      loginUsernameInputLabel.textContent = 'Username';
      loginUsernameInputLabel.style.color = 'black';
      loginUsernameInput.style.backgroundColor = 'white';
      return;
    } else if (loginUsernameInput.value.length < 3) {
      loginUsernameInput.style.backgroundColor = 'pink';
    } else {
      loginUsernameInputLabel.textContent = "Username";
      loginUsernameInput.style.backgroundColor = 'white';
    }
  }, 100);
});

registrationSignupButton.addEventListener('click', async(e) => {
  console.log(sessionVault.usernameAvailable, sessionVault.passwordCorrect);
  if (sessionVault.usernameAvailable && sessionVault.passwordCorrect) {
    console.log("All data input is correct. Trying to register.");
    e.preventDefault();
    localStorage.setItem("username", registerUsernameInput.value);
    const newPromise = new Promise((resolve) => {
      resolve (sessionVault.load(registerPasswordInput.value, registerUsernameInput.value));
    });
    newPromise.then(() => {
      sessionVault.registerUser(sessionVault.username);
      loginUsernameInput.value = "";
      loginPasswordInput.value = "";
      registerUsernameInput.value = "";
      registerPasswordInput.value = "";
      registerPasswordInputConfirm.value = "";
    });
  }
});

logInForm.addEventListener('submit', async(e) => {
  e.preventDefault();
  if (loginUsernameInput.value.length > 2 && loginPasswordInput.value.length > 5) {
    try {
      await sessionVault.load(loginPasswordInput.value, loginUsernameInput.value);
      if (sessionVault.username !== undefined) {
        const messageJSON = JSON.stringify( {messageType: "challenge", "username": sessionVault.username });
        sessionVault.ws.send(messageJSON);
        registrationForm.style.display = "none";
        backupButton.disabled = false;
        saveButton.disabled = false;
      }
    } catch(err) {
      console.log(err);
    }
  } else {
    return;
  }
  setTimeout(() => {
    loginUsernameInput.value = "";
    loginPasswordInput.value = "";
    registerUsernameInput.value = "";
    registerPasswordInput.value = "";
    registerPasswordInputConfirm.value = "";
  }, 500);
  console.log("Login attempt");
});

logoutButton.addEventListener('click', () => {
  sessionStorage.clear();
  window.location.reload();
});

userInput.addEventListener("keypress", function(event) {
  if (event.key === "Enter") {
    event.preventDefault();
    saveButton.click();
  }
});

contactButton.addEventListener('click', () => {
  if (document.getElementById('alertDiv')) {
    document.getElementById('alertDiv').remove();
  }
  const contactInputDiv = document.getElementById('contactInputDiv');
  if (contactInputDiv) {
    return;
  } else {
    const contactInputDiv = document.createElement('div');
    contactInputDiv.id = "contactInputDiv";
    contactControls.appendChild(contactInputDiv);
    const contactInput = document.createElement('input');
    contactInput.id = "contactInput";
    contactInput.autocomplete = 'off';
    const addContactButton = document.createElement('button');
    addContactButton.id = "addContactButton";
    addContactButton.textContent = "Add";
    contactInputDiv.appendChild(contactInput);
    contactInputDiv.appendChild(addContactButton);
    contactInput.focus();
    addContactButton.addEventListener('click', () => {
      const newContact = contactInput.value;
      if (newContact === null || newContact.length === 0) {
        console.log("Aborted");
        throw new Error("No contact provided");
      }
      const messageJSON = JSON.stringify({ "username": sessionVault.username, "messageType": "addConversation", "contactUsername": newContact });
      sessionVault.ws.send(messageJSON);
      console.log(messageJSON, "sent to server");
    });
    contactInput.addEventListener('keydown', (event) => {
      if (event.key === "Enter") {
        addContactButton.click();
      }
    });
    setTimeout(() => {
      document.addEventListener('click', (event) => {
        if (document.getElementById('contactControls').contains(event.target)) {
          return;
        } else {
          if (document.getElementById('alertDiv')) {
            document.getElementById('alertDiv').remove();
          }
          contactInputDiv.remove();
        }
      },);
    }, 5);
  }
});

backupButton.disabled = true;
saveButton.disabled = true;

saveButton.addEventListener('click', async () => {
  saveButton.disabled = true;
  const data = userInput.value;
  await sessionVault.encryptStoreAndSend(data);
  saveButton.disabled = false;
  userInput.value = "";
  userInput.style.height = "2rem";
});

backupButton.addEventListener('click', async () => {
  backupButton.disabled = true;
  const backupData = sessionVault.getBackupData();
  console.log(typeof backupData, backupData);
  const packages = JSON.stringify(backupData);
  const packagesBlob = new Blob([packages], { type: "application/json" });
  const backupURL = URL.createObjectURL(packagesBlob);
  backupButton.disabled = false;
  const backupLink = document.createElement('a');
  backupLink.textContent = "Download Backup";
  backupLink.target = "_blank";
  backupLink.rel = "noopener noreferrer";
  backupLink.href = backupURL;
  backupLink.download = "Backup.json";
  document.body.appendChild(backupLink);
  backupLink.style.display = 'none';
  backupLink.click();
  setTimeout(() => {
    URL.revokeObjectURL(backupURL);
    document.body.removeChild(backupLink);
  }, 50);
});

uploadBackupButton.addEventListener("click", () => {
  const file = fileUpload.files[0];
  let importedBackup;
  const reader = new FileReader();
  reader.onload = function() {
    importedBackup = JSON.parse(reader.result);
    localStorage.setItem("encryptedPackages", JSON.stringify(importedBackup.encryptedPackages));
    localStorage.setItem("encryptedWrappedKey", importedBackup.encryptedWrappedKey);
    const messageIvStart = crypto.getRandomValues(new Uint8Array(ivLength - 4));
    const messageIvEnd = new Uint8Array(4).fill(0);
    const messageIv = new Uint8Array(ivLength);
    messageIv.set(messageIvStart, 0);
    messageIv.set(messageIvEnd, messageIvStart.length);
    console.log("messageIv ", messageIv, messageIv.toString());
    localStorage.setItem("messageIv", messageIv.toBase64());
    console.log("messageIv ", messageIv, " stored in local storage: ", messageIv.toString());
    localStorage.setItem("encryptedSessionKey", importedBackup.encryptedSessionKey);
    localStorage.setItem("publicKey", importedBackup.publicKey);
    localStorage.setItem("encryptedPrivateKey", importedBackup.encryptedPrivateKey);
    localStorage.setItem("salt", importedBackup.salt);
    localStorage.setItem("wrappingIv", importedBackup.wrappingIv);
    (async () => {
      try {
        await sessionVault.load();
      } catch (e) {
        console.log("Loading failed with error: ", e);
      }
    })();
  };
  reader.readAsText(file);
  console.log(typeof sessionVault, sessionVault);
});
