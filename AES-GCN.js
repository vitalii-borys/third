const timestampLength = 3;
let password = prompt("Enter password");
if (password === null || password.length === 0) {
  console.log("Aborted");
  throw new Error("No password provided");
}
const rawPassword = new TextEncoder().encode(password);
password = "";
const saltLength = 16;
const ivLength = 12;

function storageAvailable(type) {
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
let localStorageAvailable = storageAvailable("localStorage");

function initializeStorage() {
  let messageIv, salt, wrappingIv;
  if (localStorageAvailable) {
    if (localStorage.getItem("wrappingIv") !== null) {
      wrappingIv = Uint8Array.fromBase64(localStorage.getItem("wrappingIv"));
      console.log(typeof wrappingIv, "WrappingIv from local storage: ", wrappingIv, " is: ", wrappingIv.toString());
    } else {
      wrappingIv = crypto.getRandomValues(new Uint8Array(ivLength));
      localStorage.setItem("wrappingIv", wrappingIv.toBase64());
      console.log(typeof wrappingIv, "WrappingIv ", wrappingIv, " stored in local storage: ", wrappingIv.toString());
    }
    if (localStorage.getItem("messageIv") !== null) {
      messageIv = Uint8Array.fromBase64(localStorage.getItem("messageIv"));
      console.log(typeof messageIv, "MessageIv from local storage: ", messageIv, " is: ", messageIv.toString());
    } else {
      console.log("No messageIv in local storage");
      messageIv = crypto.getRandomValues(new Uint8Array(ivLength));
      var messageIvString = messageIv.toBase64();
      localStorage.setItem("messageIv", messageIvString);
      console.log(typeof messageIvString, "First messageIv :", messageIvString, " stored in local storage.");
    }
    if (localStorage.getItem("salt") !== null) {
      salt = Uint8Array.fromBase64(localStorage.getItem("salt"));
      console.log(typeof salt, "Salt from local storage: ", salt);
    } else {
      salt = crypto.getRandomValues(new Uint8Array(saltLength));
      console.log(typeof salt, "Salt :", salt);
      var saltString = salt.toBase64();
      localStorage.setItem("salt", saltString);
      console.log(typeof saltString, "Salt :", saltString, " stored in local storage.");
    }
    return { messageIv, salt, wrappingIv };
  }
}

async function getMasterKey(password) {
  //const rawPassword = new TextEncoder().encode(password);
  const mKey = await window.crypto.subtle.importKey("raw", rawPassword, "PBKDF2", false, ["deriveKey"]);
  return mKey;
}

async function deriveWrappingKey(masterKey, salt) {
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

async function getKey() {
  const masterKey = await getMasterKey(password);
  const wrappingKey = await deriveWrappingKey(masterKey, salt);
  console.log(typeof wrappingKey, "Wrapping key is: ", wrappingKey);
  if (localStorageAvailable) {
    if (localStorage.getItem("key") !== null) {
      try {
        const decryptBuffer = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: wrappingIv,
          },
          wrappingKey,
          Uint8Array.fromBase64(localStorage.getItem("key")),
        );
        console.log(typeof decryptBuffer, "Decrypted buffer is: ", decryptBuffer);
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
          iv: wrappingIv,
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

function incrementIV(buffer) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    buffer[i]= (buffer[i] + 1) % 256;
    if (buffer[i] !== 0) {
      break;
    }
  }
}

const { messageIv, salt, wrappingIv } = initializeStorage();

async function encryptPackage(key, data) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  console.log("Encoded data: ", encodedData);
  const encryptionTimestamp = performance.now().toString().slice(0, timestampLength);
  console.log("Encryption Timestamp: ", encryptionTimestamp);
  const additionalData = encoder.encode(encryptionTimestamp);
  console.log(typeof additionalData, "Aditional data: ", additionalData);
  incrementIV(messageIv);
  localStorage.setItem("messageIv", messageIv.toBase64());
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: messageIv,
      additionalData: additionalData
    },
    key,
    encodedData,
  );
  console.log(typeof ciphertext, "Ciphered text: ", ciphertext);
  const ciphertextArray = new Uint8Array(ciphertext);
  console.log(typeof ciphertextArray, "CiphertextArray :", ciphertextArray);
  const package = new Uint8Array(timestampLength + ivLength + ciphertextArray.length);
  package.set(additionalData, 0);
  package.set(messageIv, timestampLength);
  package.set(ciphertextArray, timestampLength + ivLength);
  console.log("package :", package);
  const package64 = package.toBase64();
  console.log(typeof package64, "package64 :", package64);
  return { package64 };
}

async function decryptPackageWithKey(key, package) {
  const packageToBytes = Uint8Array.fromBase64(package);
  const receivedTimestampArray = packageToBytes.slice(0, timestampLength);
  const receivedTimestamp = new TextDecoder().decode(receivedTimestampArray);
  const receivedMessageIvArray = packageToBytes.slice(timestampLength, timestampLength + ivLength);
  const receivedCiphertextArray = packageToBytes.slice(timestampLength + ivLength);
  console.log("receivedTimestamp :", receivedTimestamp);
  console.log("receivedMessageIvArray :", receivedMessageIvArray);
  console.log("receivedCiphertextArray :", receivedCiphertextArray);
  try {
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: receivedMessageIvArray,
      additionalData: receivedTimestampArray
    },
    key,
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

(async () => {
  const data = "Hello world";
  const sessionKey = await getKey();
  const { package64: packageData } = await encryptPackage(sessionKey, data);
  try {
    const secondDecryptedData = await decryptPackageWithKey(sessionKey, packageData);
    console.log(typeof secondDecryptedData.message, "Second decrypted message: ", secondDecryptedData.message);
  } catch (e) {
    console.log("Decryption failed with error: ", e);
    return;
  }  
})();
