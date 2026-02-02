let userPassword = prompt("Enter password");
if (userPassword === null || userPassword.length === 0) {
  console.log("Aborted");
  throw new Error("No password provided");
}
//let userPassword = "12345678";
const timestampLength = 3;
const saltLength = 16;
const ivLength = 12;

class CryptoVault {
  #wrappingIv;
  #messageIv;
  #salt;
  #sessionKey;
  #localStorageAvailable;

  constructor() {
    this.#localStorageAvailable = this.storageAvailable("localStorage");
  }
  
  async load() {
    this.#sessionKey = await this.#getKey();
    return this;
  }
  
  async encryptPackage(data) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    console.log("Encoded data: ", encodedData.toString());
    const encryptionTimestamp = performance.now().toString().slice(0, timestampLength);
    console.log("Encryption Timestamp: ", encryptionTimestamp);
    const additionalData = encoder.encode(encryptionTimestamp);
    console.log("Aditional data: ", additionalData.toString());
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
    console.log("Ciphered text: ", ciphertext);
    const ciphertextArray = new Uint8Array(ciphertext);
    console.log("CiphertextArray :", ciphertextArray.toString());
    const packageData = new Uint8Array(timestampLength + ivLength + ciphertextArray.length);
    packageData.set(additionalData, 0);
    packageData.set(this.#messageIv, timestampLength);
    packageData.set(ciphertextArray, timestampLength + ivLength);
    console.log("packageData :", packageData.toString());
    const package64 = packageData.toBase64();
    console.log("package64 :", package64.toString());
    return { package64 };
  }

  async decryptPackage(packageData) {
    const packageToBytes = Uint8Array.fromBase64(packageData);
    const receivedTimestampArray = packageToBytes.slice(0, timestampLength);
    const receivedTimestamp = new TextDecoder().decode(receivedTimestampArray);
    const receivedMessageIvArray = packageToBytes.slice(timestampLength, timestampLength + ivLength);
    const receivedCiphertextArray = packageToBytes.slice(timestampLength + ivLength);
    console.log("receivedTimestamp :", receivedTimestamp);
    console.log("receivedMessageIvArray :", receivedMessageIvArray.toString());
    console.log("receivedCiphertextArray :", receivedCiphertextArray.toString());
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
    userPassword = "";
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
          console.log("Decrypted buffer is: ", decryptBuffer);
          const decryptedKey = await window.crypto.subtle.importKey(
            "raw",
            decryptBuffer,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"],
          );
          console.log(typeof decryptedKey, "Decrypted Key is: ", decryptedKey);
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
    //let messageIv, salt, wrappingIv;
    if (this.#localStorageAvailable) {
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
      return { messageIv: this.#messageIv, salt: this.#salt, wrappingIv:this.#wrappingIv };
    }
  }
  
  storageAvailable(type) {
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
        // acknowledge QuotaExceededError only if there's something already stored
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


(async () => {
  const data = "Hello world";
  const sessionCryptoVault = await new CryptoVault().load();
  const { package64: packageData } = await sessionCryptoVault.encryptPackage(data);

  try {
    const decryptedData = await sessionCryptoVault.decryptPackage(packageData);
    console.log(typeof decryptedData.message, "Decrypted message: ", decryptedData.message);
  } catch (e) {
    console.log("Decryption failed with error: ", e);
    return;
  }  
})();
