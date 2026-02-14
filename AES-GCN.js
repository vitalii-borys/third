let userPassword = prompt("Enter password");
if (userPassword === null || userPassword.length === 0) {
  console.log("Aborted");
  throw new Error("No password provided");
}
//let userPassword = "555";
const timestampLength = 8;
const saltLength = 16;
const ivLength = 12;

const userInput = document.createElement('input');
const userMessages = document.createElement('div');
const saveButton = document.createElement('button');
const decryptButton = document.createElement('button');
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
saveButton.textContent = 'Save';
decryptButton.style.fontSize = '25px';
decryptButton.style.width = '19vw';
decryptButton.textContent = 'Decrypt';
backupButton.textContent = 'Get backup link';
backupButton.style.width = '19vw';
backupButton.style.fontSize = '20px';
uploadBackupButton.textContent = 'Upload';
uploadBackupButton.style.width = '19vw';
uploadBackupButton.style.fontSize = '20px';
const bodyPage = document.body;
bodyPage.append(userInput, saveButton, userMessages, decryptButton, backupButton, uploadBackupButton, fileUpload);

class CryptoVault {
  #wrappingIv;
  #messageIv;
  #salt;
  #sessionKey;
  #localStorageAvailable;
  #encryptedPackages

  constructor() {
    this.#localStorageAvailable = CryptoVault.storageAvailable("localStorage");
  }
  
  load() {
    this.#initializeStorage();
    return this.#encryptedPackages;
  }

  getBackupData () {
    this.#initializeStorage();
    const backupJSON = {
      "encryptedPackages": this.#encryptedPackages,
      "key": localStorage.getItem("key"),
      "messageIV": localStorage.getItem("messageIv"),
      "salt": localStorage.getItem("salt"),
      "wrappingIv": localStorage.getItem("wrappingIv")
    };
    return backupJSON;
  }

  async loadAndEncrypt(userInput) {
    this.#sessionKey = await this.#getKey();
    const { package64: packageData } = await this.encryptPackage(userInput);
    this.#encryptedPackages.messages.push({id: this.#encryptedPackages.messages[this.#encryptedPackages.messages.length - 1].id + 1, text: packageData})
    localStorage.setItem("encryptedPackages", JSON.stringify({messages: this.#encryptedPackages.messages}));
    return this;
  }

  async loadAndDecrypt() {
    this.#sessionKey = await this.#getKey();
    userMessages.innerHTML = "";
    for (let i = 1; i < this.#encryptedPackages.messages.length; i++) {
      let decryptedData = await this.decryptPackage(this.#encryptedPackages.messages[i].text);
      console.log("Decrypted message: ", decryptedData.message,
        "Received time: ", new Date(Number(decryptedData.receivedTimestamp)));
      let messagediv = document.createElement('div');
      messagediv.style.fontSize = '24px';
      messagediv.textContent = decryptedData.message + " " + new Date(Number(decryptedData.receivedTimestamp));
      userMessages.append(messagediv);
    }
    return this;
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
    console.log("package64 :", package64.toString());
    return { package64 };
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
    return wrappingKey;
  }

  async #getKey() {
    this.#initializeStorage();
    var rawPassword = new TextEncoder().encode(userPassword);
    //userPassword = "";
    const masterKey = await this.getMasterKey(rawPassword);
    rawPassword = null;
    const wrappingKey = await this.deriveWrappingKey(masterKey, this.#salt);
    console.log("Wrapping key is: ", wrappingKey);
    if (this.#localStorageAvailable) {
      if (localStorage.getItem("key") !== null) {
        try {
          const decryptBuffer = await crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: this.#wrappingIv,
            },
            wrappingKey,
            Uint8Array.fromBase64(localStorage.getItem("key")),
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
        localStorage.setItem("key", encryptedWrappedKey);
        return generatedKey;
      }
    } else {
      console.log("Too bad, no local storage for us.");
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

saveButton.addEventListener('click', async () => {
  const data = userInput.value;
  saveButton.disabled = true;
  await new CryptoVault().loadAndEncrypt(data);
  saveButton.disabled = false;
  userInput.value = "";
});

decryptButton.addEventListener('click', async () => {
  try {
    decryptButton.disabled = true;
    await new CryptoVault().loadAndDecrypt();
    decryptButton.disabled = false;
  } catch (e) {
    console.log("Decryption failed with error: ", e);
    return;
  }
});

backupButton.addEventListener('click', async () => {
  backupButton.disabled = true;
  const backupPackegesJSON = await new CryptoVault().getBackupData();
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
  /* backupLink.addEventListener('click', () => {
    backupLink.style.display = 'none';
    setTimeout(() => {
      URL.revokeObjectURL(backupURL);
      backupLink.remove();
    }, 1000);
  }); */
  backupLink.click();
  document.body.removeChild(backupLink);
});

uploadBackupButton.addEventListener("click", () => {
  const file = fileUpload.files[0];
  let myImportedJSON;
  const reader = new FileReader();
  reader.onload = function() {
    myImportedJSON = JSON.parse(reader.result);
    localStorage.setItem("encryptedPackages", JSON.stringify(myImportedJSON.encryptedPackages));
    localStorage.setItem("key", myImportedJSON.key);
    localStorage.setItem("messageIv", myImportedJSON.messageIV);
    localStorage.setItem("salt", myImportedJSON.salt);
    localStorage.setItem("wrappingIv", myImportedJSON.wrappingIv);
  };
  reader.readAsText(file);
});
