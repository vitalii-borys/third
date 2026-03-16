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
  #encryptedPackages;
  timeOptions = {
    timeZone: 'Europe/Kiev',
    dateStyle: 'short',
    timeStyle: 'short',
  };
  days = ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
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
      let decryptedData = await sessionVault.decryptPackage(message.text);
      console.log("initial currentMessageId", this.currentMessageId);
      this.currentMessageId++;
      console.log("currentMessageId after decrypting initial server message", this.currentMessageId);
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
      console.log("currentMessageId before removal:", this.currentMessageId);
      this.currentMessageId++;
      console.log("currentMessageId after removal:", this.currentMessageId);
    });
    updateButton.addEventListener('click', () => {
      const inputElement = document.createElement('input');
      inputElement.type = 'text';
      inputElement.style.all = 'inherit';
      inputElement.style.backgroundColor = 'white';
      inputElement.value = divToRemove.children[0].innerText;
      divToRemove.children[0].replaceWith(inputElement);
      inputElement.focus();
      inputElement.addEventListener('keypress', async (e) => {
        if (e.key === 'Enter') {
          const updatedDiv = document.createElement("div");
          updatedDiv.classList = "mes";
          let newMessage;
          try {
            newMessage = await sessionVault.encryptPackage(inputElement.value);
          } catch (e) {
            console.log("Error", e);
          }
          updatedDiv.textContent = inputElement.value;
          inputElement.replaceWith(updatedDiv);
          const messageJSON = JSON.stringify({ "id": messageId, "text": newMessage, "username": sessionVault.username, "messageType": "update" });
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

  connect(wsServerLocation) {
    this.forceClose = false;
    this.ws = new WebSocket(this.websocketServerLocation);

    this.ws.onopen = () => {
      console.log("Connected to server");
      this.reconnectionAttempts = 0;
      const messageJSON = JSON.stringify({ "messageType": "hello", "username": this.username });
      this.ws.send(messageJSON);
    };
    // have to implement client send message logic to fail sending message when server is down by checking ws.readyState
    this.ws.onmessage = async(message) => {
      const messageData = JSON.parse(message.data);
      console.log(messageData);
      switch(messageData.messageType) {
        case "initialMessage": {
          userMessages.innerHTML = "";
          for (const msg of messageData.messages) {
            await this.handleMessage(msg);
          }
          scrollToBottom();
        }
        break;
        case "auth": {
          const serverKeyPair = await this.#generateKeyPair("server");
          const serverPublicKey = (serverKeyPair).publicKey;
          const serverPrivateKey = (serverKeyPair).privateKey;
          this.serverPublicKey = serverPublicKey;
          this.#serverPrivateKey = serverPrivateKey;
          const exportedPublicKey = await crypto.subtle.exportKey("spki", this.serverPublicKey);
          const publicKeyBuffer = new Uint8Array(exportedPublicKey).toBase64();
          const signatureForServer = await this.signData(messageData.text);
          const messageJSON = JSON.stringify({ "messageType": "auth", "text": signatureForServer, "publicKey": publicKeyBuffer, "username": this.username });
          this.ws.send(messageJSON);
          console.log(messageJSON, "sent");
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
          this.connect(wsServerLocation);
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


  getUsername() {
    let username;
    if (localStorage.getItem("username") !== null && localStorage.getItem("username") !== "undefined") {
      username = localStorage.getItem("username");
      console.log("Username from local storage: ", username);
      this.username = username;
    } else {
      let username = prompt("Enter username");
      if (username === null || username.length === 0) {
        console.log("Aborted");
        throw new Error("No username provided");
      }
      this.username = username;
      localStorage.setItem("username", username);
      console.log("No username in local storage: ", username, " created.");
    }
  }

  async load() {
    this.getUsername();
    let userPassword = 333;
    /* userPassword = prompt("Enter password");
    if (userPassword === null || userPassword.length === 0) {
      console.log("Aborted");
      throw new Error("No password provided");
    } */
    this.#sessionKey = await this.#getKey(userPassword);
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
    const encodedData = enc.encode(data)
    console.log(data, this.#serverPrivateKey);
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
    const userMessage = this.createMessageElement(userInput, messageTime, this.currentMessageId);
    console.log(packageData, messageTime, this.currentMessageId);
    const messageJSON = JSON.stringify({ "text": packageData, "username": this.username, "messageType": "message" });
    this.ws.send(messageJSON);
    userMessages.append(userMessage);
    console.log("currentMessageId before sending:", this.currentMessageId);
    this.currentMessageId++;
    console.log("currentMessageId after sending:", this.currentMessageId);
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
  
  async encryptPackage(data) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const additionalData = this.#bigintToUint8Buffer(BigInt(Date.now()));
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

  async encryptAndStorePrivatePublicKeys() {
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("encryptedSessionKey") !== null && localStorage.getItem("encryptedPrivateKey") !== null && localStorage.getItem("publicKey") !== null) {
        const publicKeyBuffer = Uint8Array.fromBase64(localStorage.getItem("publicKey"));
        const publicKey = await crypto.subtle.importKey(
          "spki",
          publicKeyBuffer,
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"]
        );
        this.clientPublicKey = publicKey;
        //console.log("Public key from local storage is:", this.publicKey);
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
        //console.log("Private key (client) from local storage is:", this.#clientPrivateKey);
      } else {
        const clientKeyPair = this.#generateKeyPair("server");
        const clientPublicKey = (await clientKeyPair).publicKey;
        this.clientPublicKey = clientPublicKey;
        console.log(clientPublicKey);
        const exportedPublicKey = await crypto.subtle.exportKey("spki", clientPublicKey);
        console.log(exportedPublicKey);
        console.log(new Uint8Array(exportedPublicKey).toBase64(), "will go to local storage");
        localStorage.setItem("publicKey", new Uint8Array(exportedPublicKey).toBase64())
        const clientPrivateKey = (await clientKeyPair).privateKey;
        this.#clientPrivateKey = clientPrivateKey;
        console.log(clientPrivateKey);
        console.log("No key pair in local storage so newely generated keys are: ", clientPublicKey, clientPrivateKey);
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
        console.log(sessionKeyBufferString, "will go to local storage");
        localStorage.setItem("encryptedSessionKey", sessionKeyBufferString);
        
        const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#clientPrivateKey);
        console.log(exportedPrivateKey);
        const privateKeyBuffer = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: this.#wrappingIv
          },
          this.#wrappingKey,
          exportedPrivateKey
        );
        const privateKeyBufferString = new Uint8Array(privateKeyBuffer).toBase64();
        console.log(privateKeyBufferString, "will go to local storage");
        localStorage.setItem("encryptedPrivateKey", privateKeyBufferString);
      }
    }
  }

  #initializeStorage() {
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("encryptedPackages") !== null) {
        this.#encryptedPackages = JSON.parse(localStorage.getItem("encryptedPackages"));
        console.log("Encrypted packages from local storage: ", this.#encryptedPackages);
      } else {
        localStorage.setItem("encryptedPackages", JSON.stringify({messages: [{id: 0, text: ""}]}));
        this.#encryptedPackages = JSON.parse(localStorage.getItem("encryptedPackages"));
        console.log("No encrypted packages in local storage: ", this.#encryptedPackages, " created.");
      }
      if (localStorage.getItem("wrappingIv") !== null) {
        this.#wrappingIv = Uint8Array.fromBase64(localStorage.getItem("wrappingIv"));
        console.log("WrappingIv from local storage is: ", this.#wrappingIv.toString());
      } else {
        this.#wrappingIv = crypto.getRandomValues(new Uint8Array(ivLength));
        localStorage.setItem("wrappingIv", this.#wrappingIv.toBase64());
        console.log(typeof this.#wrappingIv, "WrappingIv ", this.#wrappingIv, " stored in local storage: ", this.#wrappingIv.toString());
      }
      if (localStorage.getItem("messageIv") !== null) {
        this.#messageIv = Uint8Array.fromBase64(localStorage.getItem("messageIv"));
        console.log("MessageIv from local storage: ", this.#messageIv.toString());
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
        console.log("Salt from local storage: ", this.#salt.toString());
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

userInput.addEventListener("keypress", function(event) {
  if (event.key === "Enter") {
    event.preventDefault();
    saveButton.click();
  }
});

backupButton.disabled = true;
saveButton.disabled = true;
let sessionVault = new CryptoVault();
(async () => {
  try {
    await sessionVault.load();
    await sessionVault.encryptAndStorePrivatePublicKeys();
    //await sessionVault.loadAndDecrypt();
    backupButton.disabled = false;
    saveButton.disabled = false;
    sessionVault.connect(sessionVault.websocketServerLocation);
    return sessionVault;
  } catch (e) {
    console.log("Loading failed with error: ", e);
  }
})();

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
