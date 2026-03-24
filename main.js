//let userPassword = "555";

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
const signupButton = document.getElementById('signupButton');
const registrationSignupButton = document.getElementById('registrationSignupButton');
const backToLogin = document.getElementById('backToLogin');
const loginUsernameInputLabel = document.getElementById('loginUsernameInputLabel');
const loginPasswordInputLabel = document.getElementById('loginPasswordInputLabel');
const registerPasswordInput = document.getElementById('registerPasswordInput');
const registerPasswordInputConfirm = document.getElementById('registerPasswordInputConfirm');
const registerUsernameInputLabel = document.getElementById('registerUsernameInputLabel');
const registerPasswordInputLabel = document.getElementById('registerPasswordInputLabel');
const registerPasswordInputConfirmLabel = document.getElementById('registerPasswordInputConfirmLabel');

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
  role;
  #encryptedPackages;
  timeOptions = {
    timeZone: 'Europe/Kiev',
    dateStyle: 'short',
    timeStyle: 'short',
  };
  days = ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
  months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  ws = null;
  websocketServerLocation = "ws://localhost:8080";
  maxReconnectInterval = 60000;
  reconnectionAttempts = 0;
  forceClose = false;
  currentMessageId = 0;

  constructor() {
    this.#localStorageAvailable = CryptoVault.storageAvailable("localStorage");
  }

  disconnect() {
    this.forceClose = true;
    if (ws) {
      ws.close();
    }
  }

  async handleMessage(message) {
    try {
      let decryptedData = await sessionVault.decryptPackage(message.messageText);
      this.currentMessageId = message.id;
      console.log("this.currentMessageId", this.currentMessageId);
      const messageDiv = this.createMessageElement(decryptedData.message, decryptedData.receivedTimestamp, message.id);
      userMessages.append(messageDiv);
    } catch (e) {
      console.log("Server message decryption failed.", e);
    }
  }

  createMessageElement = function(message, timestamp, id) {
    const messageDiv = document.createElement('div');
    const messageTime = new Date(Number(timestamp));
    const formatted = `${String(messageTime.getHours()).padStart(2, 0)}:${String(messageTime.getMinutes()).padStart(2, 0)}`;
    messageDiv.classList = "message";
    const dayName = this.days[messageTime.getDay()];
    let mes = document.createElement('div');
    let mesDay = document.createElement('div');
    let mesTime = document.createElement('div');
    mes.classList = "mes";
    mesDay.classList = "mesDay";
    mesTime.classList = "mesTime";
    mes.textContent = message;
    mesDay.textContent = `${dayName}`;
    mesTime.textContent = formatted;
    messageDiv.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      this.createContextMenu(e.pageX, e.pageY, id, messageDiv);
    });
    messageDiv.append(mes, mesDay, mesTime);
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
      const messageJSON = JSON.stringify({ "id": messageId, "username": sessionVault.username, "messageType": "delete" });
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
          updatedDiv.classList = "mes";
          let newMessage;
          try {
            newMessage = await sessionVault.encryptPackage(inputElement.value, messageToEditTimestamp);
          } catch (e) {
            console.log("Error", e);
          }
          updatedDiv.textContent = inputElement.value;
          inputElement.replaceWith(updatedDiv);
          const messageJSON = JSON.stringify({ "id": messageId, "messageText": newMessage, "username": sessionVault.username, "messageType": "update" });
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
    const messageJSON = JSON.stringify({ "messageType": "register", "username": username, "publicKey": publicKeyBuffer });
    this.ws.send(messageJSON);
    console.log(messageJSON, "sent to server");
  }

  connect() {
    this.forceClose = false;
    this.ws = new WebSocket(this.websocketServerLocation);
    this.ws.onopen = async () => {
      console.log("Connected to server");
      this.username = localStorage.getItem("username");
      console.log(this.username, "assigned from local storage")
      this.reconnectionAttempts = 0;
    };
      
    // have to implement client send message logic to fail sending message when server is down by checking ws.readyState
    this.ws.onmessage = async(message) => {
      const messageData = JSON.parse(message.data);
      switch(messageData.messageType) {
        case "checkUsername": {
          if (messageData.messageText !== undefined) {
            registerUsernameInputLabel.textContent = `"Username ${messageData.username} ${messageData.messageText}`;
            registerUsernameInputLabel.style.color = 'pink';
          } else {
            if (!messageData.available) {
              registerUsernameInputLabel.textContent = `"Username ${messageData.username} is not available`;
              registerUsernameInputLabel.style.color = 'pink';
            } else {
              registerUsernameInputLabel.textContent = `Username ${messageData.username} is available`;
              registerUsernameInputLabel.style.color = 'lightgreen';
            }
            console.log(messageData);
          }
        }
        break;
        case "registrationSuccess": {
          registerPasswordInput.value = "";
          registerPasswordInputConfirm.value = "";
          registerUsernameInput.value = "";
          console.log(messageData);
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
          const alertDiv = document.getElementById('alertDiv');
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
          logInForm.style.display = "none";
          chatDiv.style.display = "flex";
          backupControls.style.display = "flex";
          contactContainer.style.display = "flex";

          if (messageData.userRole === "admin") {
            this.role = "admin";
            console.log(this.role, "is yor role");            
            const adminbutton = document.getElementById("adminButton");
            adminbutton.style.display = "flex";
            const adminTable = document.getElementById("adminTable");
            const adminTableBody = document.getElementById("adminTableBody");
            adminbutton.addEventListener('click', () => {
              if (adminbutton.textContent === "Show database") {
                adminbutton.textContent = "Hide database";
                adminTable.style.display = "block";
              } else {
                adminTableBody.innerHTML = "";
                adminbutton.textContent = "Show database";
                adminTable.style.display = "none";
              }
              if (sessionVault.role === "admin") {
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
              } else if (sessionVault.role === "user") {
                console.log("You are user");
              } else {
                console.log("Role is not set");
              }
            });
          } else if (messageData.role === "user") {
            this.role = "user";
            console.log(this.role, "is yor role");
          }
          userMessages.innerHTML = "";
          for (const msg of messageData.messages) {
            await this.handleMessage(msg);
          }
          contactDiv.innerHTML = "";
          const userContacts = JSON.parse(messageData.user.contacts);
          userContacts.forEach(contact => {
            const newContactDiv = document.createElement('div');
            newContactDiv.classList = "newContactDiv";
            newContactDiv.textContent = contact;
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
          document.getElementById("contactInput").value = "";
        }
        break;
        case "auth": {
          const signatureForServer = await this.signData(messageData.messageText);
          const messageJSON = JSON.stringify({ "messageType": "auth", "messageText": signatureForServer, "username": this.username });
          this.ws.send(messageJSON);
          //console.log(messageJSON, "sent");
        }
        break;
      }
    }

    this.ws.onclose = () => {
      if (this.forceClose) {
        this.disconnect();
        console.log("Disconnected manually. Stopping reconnection.");
        return;
      }

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
      ws.close();
      ws.onerror = null;
    }
  }

  async load(userPassword, username, registerUser) {
    this.username = username;
    this.#sessionKey = await this.#getKey(userPassword);
    await sessionVault.encryptAndStorePrivatePublicKeys(registerUser);
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
    const enc = new TextEncoder();
    const encodedData = enc.encode(data);
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
    const messageJSON = JSON.stringify({ "id": this.currentMessageId, "messageText": packageData, "username": this.username, "messageType": "message" });
    this.ws.send(messageJSON);
    console.log(messageJSON);
    userMessages.append(userMessage);
    scrollToBottom();
  }

  #bigintToUint8Buffer (bigInt) {
    let dv = new DataView(new ArrayBuffer(8), 0);
    dv.setBigUint64(0, bigInt);
    let uArr = new Uint8Array(dv.buffer);
    return uArr;
  }

  #uint8ArrayToBigint (bigIntBuffer) {
    let dv = new DataView(bigIntBuffer.buffer, 0);
    let myBigInt = dv.getBigUint64();
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

  async getMasterKey(rawPassword) {
    const mKey = await window.crypto.subtle.importKey("raw", rawPassword, "PBKDF2", false, ["deriveKey"]);
    return mKey;
  }

  async deriveWrappingKey(masterKey, salt) {
    const wrappingKey = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
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
    return wrappingKey;
  }
  
  async #getKey(userPassword) {
    this.#initializeStorage();
    var rawPassword = new TextEncoder().encode(userPassword);
    userPassword = "";
    const masterKey = await this.getMasterKey(rawPassword);
    rawPassword = null;
    const wrappingKey = await this.deriveWrappingKey(masterKey, this.#salt);
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

  async #generateKeyPair(destination) {
    let keyPair = null;
    if (destination === "server") {
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
    } else if (destination === "client") {      
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

  async encryptAndStorePrivatePublicKeys(registerUser) {
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
        const clientKeyPair = this.#generateKeyPair("client");
        const serverKeyPair = this.#generateKeyPair("server");
        
        const clientPublicKey = (await clientKeyPair).publicKey;
        const clientPrivateKey = (await clientKeyPair).privateKey;
        this.clientPublicKey = clientPublicKey;
        this.#clientPrivateKey = clientPrivateKey;
        console.log("No key pair in local storage so newely generated keys are: ", clientPublicKey, clientPrivateKey);
        
        const exportedPublicKey = await crypto.subtle.exportKey("spki", clientPublicKey);
        localStorage.setItem("publicKey", new Uint8Array(exportedPublicKey).toBase64())
        
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
        
        const serverPublicKey = (await serverKeyPair).publicKey;
        const serverPrivateKey = (await serverKeyPair).privateKey;
        this.serverPublicKey = serverPublicKey;
        this.#serverPrivateKey = serverPrivateKey;
        console.log("No key pair in local storage so newely generated server keys are: ", serverPublicKey, serverPrivateKey);

        const exportedServerPublicKey = await crypto.subtle.exportKey("spki", serverPublicKey);
        localStorage.setItem("serverPublicKey", new Uint8Array(exportedServerPublicKey).toBase64())
        
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
    if (registerUser) {
      this.registerUser(this.username);
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

let sessionVault = new CryptoVault();
sessionVault.connect();

let timeoutID;
registerPasswordInputConfirm.addEventListener('input', () => {
  clearTimeout(timeoutID);
  timeoutID = setTimeout(() => {
    if (registerPasswordInputConfirm.value.length === 0) {
      registerPasswordInputConfirmLabel.textContent = 'Write password';
      registerPasswordInputConfirmLabel.style.color = 'black';
      registerPasswordInputConfirm.style.backgroundColor = 'white';
    } else if (registerPasswordInputConfirm.value !== registerPasswordInput.value) {
      registerPasswordInputConfirmLabel.textContent = "Passwords don't match";
      registerPasswordInputConfirm.style.backgroundColor = 'pink';
    } else {
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
    const messageJSON = JSON.stringify({ "messageType": "checkUsername", "username": registerUsernameInput.value });
    sessionVault.ws.send(messageJSON);
    console.log(messageJSON, "sent to server");
  }, 100);
});

loginPasswordInput.addEventListener('keypress', (event) => {
  if (event.key === "Enter") {
    loginButton.click();
  }
});

loginButton.addEventListener('click', async() => {
  const promiseToLoad = new Promise(async(resolve) => {
    resolve(await sessionVault.load(loginPasswordInput.value, loginUsernameInput.value, false));
  });
  promiseToLoad.then(async () => {
    if (sessionVault.username !== undefined) {
      const messageJSON = JSON.stringify({ "messageType": "challenge", "username": sessionVault.username });
      sessionVault.ws.send(messageJSON);
      loginUsernameInput.value = "";
      loginPasswordInput.value = "";
      registerPasswordInput.value = "";
      registerPasswordInputConfirm.value = "";
      registrationForm.style.display = "none";
      backupButton.disabled = false;
      saveButton.disabled = false;
    }
  });
});

registrationSignupButton.addEventListener('click', async() => {
  localStorage.setItem("username", registerUsernameInput.value)
  try {
    await sessionVault.load(registerPasswordInput.value, registerUsernameInput.value, true);
  } catch (e) {
    console.log("Loading failed with error: ", e);
  }
  loginUsernameInput.value = "";
  loginPasswordInput.value = "";
});

signupButton.addEventListener('click', () => {
  loginUsernameInputLabel.textContent = "Username";
  loginUsernameInputLabel.style.color = "black";
  loginUsernameInput.value = "";
  loginPasswordInput.value = "";
  logInForm.style.display = 'none';
  registrationForm.style.display = 'flex';
});

backToLogin.addEventListener('click', () => {
  registrationForm.style.display = 'none';
  logInForm.style.display = 'flex';
  loginUsernameInput.style.backgroundColor = 'white';
});

userInput.addEventListener("keypress", function(event) {
  if (event.key === "Enter") {
    event.preventDefault();
    saveButton.click();
  }
});

contactButton.addEventListener('click', () => {
  const contactInputDiv = document.createElement('div');
  contactInputDiv.id = "contactInputDiv";
  contactControls.appendChild(contactInputDiv);
  const contactInput = document.createElement('input');
  contactInput.id = "contactInput";
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
    const messageJSON = JSON.stringify({ "username": sessionVault.username, "messageType": "addContact", "contactUsername": newContact });
    sessionVault.ws.send(messageJSON);
    console.log(messageJSON, "sent to server");
  });
  contactInput.addEventListener('keydown', (event) => {
    if (event.key === "Enter") {
      addContactButton.click();
    }
  });
});

backupButton.disabled = true;
saveButton.disabled = true;

saveButton.addEventListener('click', async () => {
  saveButton.disabled = true;
  const data = userInput.value;
  await sessionVault.encryptStoreAndSend(data);
  saveButton.disabled = false;
  userInput.value = "";
});

backupButton.addEventListener('click', async () => {
  backupButton.disabled = true;
  const backupPackegesJSON = sessionVault.getBackupData();
  console.log(typeof backupPackegesJSON, backupPackegesJSON);
  const packages = JSON.stringify(backupPackegesJSON);
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
  }, 500);
});

uploadBackupButton.addEventListener("click", () => {
  const file = fileUpload.files[0];
  let myImportedJSON;
  const reader = new FileReader();
  reader.onload = function() {
    myImportedJSON = JSON.parse(reader.result);
    localStorage.setItem("encryptedPackages", JSON.stringify(myImportedJSON.encryptedPackages));
    localStorage.setItem("encryptedWrappedKey", myImportedJSON.encryptedWrappedKey);
    const messageIvStart = crypto.getRandomValues(new Uint8Array(ivLength - 4));
    const messageIvEnd = new Uint8Array(4).fill(0);
    const messageIv = new Uint8Array(ivLength);
    messageIv.set(messageIvStart, 0);
    messageIv.set(messageIvEnd, messageIvStart.length);
    console.log("messageIv ", messageIv, messageIv.toString());
    localStorage.setItem("messageIv", messageIv.toBase64());
    console.log("messageIv ", messageIv, " stored in local storage: ", messageIv.toString());
    localStorage.setItem("encryptedSessionKey", myImportedJSON.encryptedSessionKey);
    localStorage.setItem("publicKey", myImportedJSON.publicKey);
    localStorage.setItem("encryptedPrivateKey", myImportedJSON.encryptedPrivateKey);
    localStorage.setItem("salt", myImportedJSON.salt);
    localStorage.setItem("wrappingIv", myImportedJSON.wrappingIv);
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
