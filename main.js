//let userPassword = "555";
const timeOptions = {
    timeZone: 'Europe/Kiev',
    dateStyle: 'short',
    timeStyle: 'short',
};

let ws = null;
const websocketServerLocation = "ws://localhost:8080";
const maxReconnectInterval = 60000;
let reconnectionAttempts = 0;
let forceClose = false;
const serverMessages = [];

function disconnect() {
  forceClose = true;
  if (ws) {
    ws.close();
  }
}

function connect(wsServerLocation) {
  forceClose = false;
  ws = new WebSocket(websocketServerLocation);

  ws.onopen = () => {
    console.log("Connected to server");
    reconnectionAttempts = 0;
  };
// have to implement client send message logic to fail sending message when server is down by checking ws.readyState
  ws.onmessage = async(message) => {
    const messageData = JSON.parse(message.data);
    for (let i = 0; i < messageData.length; i++) {
      serverMessages.push(messageData[i].text);
    }
    userMessages.innerHTML = "";
    try {        
      for (let i = 0; i < serverMessages.length; i++) {
        let decryptedData = await sessionVault.decryptPackage(serverMessages[i]);
        console.log("Decrypted message: ", decryptedData.message,
          "Received time: ", new Date(Number(decryptedData.receivedTimestamp)).toLocaleString('en-US', timeOptions));
        let messagediv = document.createElement('div');
        messagediv.style.fontSize = '24px';
        const messageTime = new Date(Number(decryptedData.receivedTimestamp));
        const UAFormatted = messageTime.toLocaleString('en-US', timeOptions);
        messagediv.textContent = decryptedData.message + " " + UAFormatted;
        userMessages.append(messagediv);
      }
    } catch (e) {
      console.log("Server message decrytion failed.", e);
    }
  };

  ws.onclose = () => {
    if (forceClose) {
      disconnect();
      console.log("Disconnected manually. Stopping reconnection.");
      return;
    }

    reconnectionAttempts++;
    const baseWait = Math.min(maxReconnectInterval, 3000 * Math.pow(2, reconnectionAttempts - 1));
    const jitter = Math.random() * (baseWait * 0.25);
    const reconnectInterval = baseWait + jitter;
    console.log("Connection closed. Reconnecting after", reconnectInterval, "ms", ws.readyState);
    setTimeout(() => {
      if (!forceClose) {
        connect(wsServerLocation);
      }
    }, reconnectInterval);
    ws.onclose = null;
  }
  
  ws.onerror = () => {
    console.log("Error. Ready state:", ws.readyState);
    ws.close();
    ws.onerror = null;
  }
}

const timestampLength = 8;
const saltLength = 16;
const ivLength = 12;

const userInput = document.createElement('input');
const userMessages = document.createElement('div');
const saveButton = document.createElement('button');
const backupButton = document.createElement('button');
const uploadBackupButton = document.createElement('button');
const fileUpload = document.createElement('input');
fileUpload.type = 'file';
fileUpload.accept = 'application/json';
userInput.style.fontSize = '25px';
userInput.id = 'user_input';
userInput.style.width = '80vw';
saveButton.style.fontSize = '25px';
saveButton.style.width = '19vw';
saveButton.textContent = 'Send';
backupButton.textContent = 'Get backup link';
backupButton.style.width = '19vw';
backupButton.style.fontSize = '20px';
uploadBackupButton.textContent = 'Upload backup';
uploadBackupButton.style.width = '19vw';
uploadBackupButton.style.fontSize = '20px';
const bodyPage = document.body;
bodyPage.append(userInput, saveButton, userMessages, backupButton, uploadBackupButton, fileUpload);

class CryptoVault {
  #wrappingIv;
  #messageIv;
  #salt;
  #sessionKey;
  #localStorageAvailable;
  #publicKey;
  #privateKey;
  #wrappingKey;
  username;
  #encryptedPackages;

  constructor() {
    this.#localStorageAvailable = CryptoVault.storageAvailable("localStorage");
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
    let userPassword;
    userPassword = prompt("Enter password");
    if (userPassword === null || userPassword.length === 0) {
      console.log("Aborted");
      throw new Error("No password provided");
    }
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

  async encryptStoreAndSend(userInput) {
    if (userInput === "") {
      return;
    }
    const packageData = await this.encryptPackage(userInput);
    this.#encryptedPackages.messages.push({id: this.#encryptedPackages.messages[this.#encryptedPackages.messages.length - 1].id + 1, text: packageData})
    localStorage.setItem("encryptedPackages", JSON.stringify({messages: this.#encryptedPackages.messages}));
    let messagediv = document.createElement('div');
    const messageTime = new Date();
    const UAformatted = messageTime.toLocaleString('en-US', timeOptions);
    messagediv.textContent = userInput + " " + UAformatted;
    messagediv.style.fontSize = '24px';
    userMessages.append(messagediv);
    const messageJSON = JSON.stringify({ "text": packageData, "username": this.username });
    console.log(typeof messageJSON, messageJSON);
    ws.send(messageJSON);
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

  async #generateKeyPair() {
    const keyPair = window.crypto.subtle.generateKey(
      {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    )
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
        this.#publicKey = publicKey;
        //console.log("Public key from local storage is:", this.#publicKey);
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
        this.#privateKey = privateKey;
        //console.log("Private key from local storage is:", this.#privateKey);
      } else {
        const keyPair = this.#generateKeyPair();
        const publicKey = (await keyPair).publicKey;
        const exportedPublicKey = await crypto.subtle.exportKey("spki", publicKey);
        localStorage.setItem("publicKey", new Uint8Array(exportedPublicKey).toBase64())
        const privateKey = (await keyPair).privateKey;
        console.log("No key pair in local storage so newely generated keys are: ", publicKey, privateKey);
        const exportedSessionKey = await crypto.subtle.exportKey("raw", this.#sessionKey);
        const sessionKeyBuffer = await crypto.subtle.encrypt(
          {
            name: "RSA-OAEP"
          },
          publicKey,
          exportedSessionKey
        );
        const sessionKeyBufferString = new Uint8Array(sessionKeyBuffer).toBase64();
        localStorage.setItem("encryptedSessionKey", sessionKeyBufferString);
        
        const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8" , privateKey);
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
    connect(websocketServerLocation);
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
    localStorage.setItem("messageIv", myImportedJSON.messageIV);
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
