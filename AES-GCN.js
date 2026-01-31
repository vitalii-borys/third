const timestampLength = 3;
//const start = performance.now();
const password = "12345678";
var salt;
const saltLength = 16;
let localStorageAvailable;
const ivLength = 12;
var iv;

const rawPassword = new TextEncoder().encode(password);

// Check if local storage is available
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
localStorageAvailable = storageAvailable("localStorage");

function initializeStorage() {
  if (localStorageAvailable) {
      // Read or generate IV
    if (localStorage.getItem("iv") !== null) {
      iv = Uint8Array.fromBase64(localStorage.getItem("iv"));
      console.log(typeof iv, "iv from local storage: ", iv);
    } else {
      console.log("No iv in local storage");
      iv = crypto.getRandomValues(new Uint8Array(ivLength));
      var ivString = iv.toBase64();
      localStorage.setItem("iv", ivString);
      console.log(typeof ivString, "First iv :", ivString, " stored in local storage.");
    }
    // Read or generate salt
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
  }
}

async function getKey() {
  const baseKey = await window.crypto.subtle.importKey("raw", rawPassword, "PBKDF2", false, ["deriveKey"]);
  console.log(typeof baseKey," Base key:", baseKey);
  // Generate and export a random key
  if (localStorageAvailable) {
    // Read or generate key
    if (localStorage.getItem("key") !== null) {
      const secretKey = await window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
      console.log(typeof secretKey, "Secret key is: ", secretKey);
      const importedKeyString = localStorage.getItem("key");
      console.log(typeof importedKeyString, "Imported Key String is: ", importedKeyString);
      const importedKeyBuffer = Uint8Array.fromBase64(importedKeyString);
      console.log(typeof importedKeyBuffer, "Imported Key Buffer is: ", importedKeyBuffer);
      const exportedSecretKey = await window.crypto.subtle.exportKey("raw", secretKey);
      console.log(typeof exportedSecretKey, "Exported Imported key is: ", exportedSecretKey);
      const exportedSeretKeyBuffer = new Uint8Array(exportedSecretKey);
      console.log(typeof exportedSeretKeyBuffer, "Exported Imported key buffer is: ", exportedSeretKeyBuffer);
      const exportedSecretKeyBufferFromStorage = Uint8Array.fromBase64(importedKeyString);
      console.log(typeof exportedSecretKeyBufferFromStorage, "Exported Secret Key Buffer From Storage is: ", exportedSecretKeyBufferFromStorage);
      const decryptBuffer = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        },
        secretKey,
        exportedSecretKeyBufferFromStorage,
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
      const exportedKeyBuffer = new Uint8Array(exportedKey);
      console.log(typeof exportedKeyBuffer, "Exported Key Buffer is: ", exportedKeyBuffer);
      const secretKey = await window.crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
      console.log(typeof secretKey, "Secret key is: ", secretKey);
      const encryptedSecretKey = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
        },
        secretKey,
        exportedKeyBuffer,
      );
      console.log(typeof encryptedSecretKey, "Encrypted secret key is: ", encryptedSecretKey);
      const encryptedSecretKeyBuffer = new Uint8Array(encryptedSecretKey);
      console.log(typeof encryptedSecretKeyBuffer, "Exported encrypted key buffer is: ", encryptedSecretKeyBuffer);
      const encryptedSecretKey64 = encryptedSecretKeyBuffer.toBase64();
      console.log(typeof encryptedSecretKey64, "Exported encrypted key is: ", encryptedSecretKey64);
      localStorage.setItem("key", encryptedSecretKey64);
      console.log("Encrypted key was written to local storage.");
      return secretKey;
    }
  } else {
    console.log("Too bad, no local storage for us.");
  }
}

// Function to increment the IV
function incrementIV(buffer) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    buffer[i]= (buffer[i] + 1) % 256;
    if (buffer[i] !== 0) {
      break;
    }
  }
}

var salt = crypto.getRandomValues(new Uint8Array(saltLength));

function importBaseKey(rawKey) {
  return window.crypto.subtle.importKey("raw", rawKey, "PBKDF2", false, ["deriveKey"]
  );
}

function deriveSecretKey(baseKey, salt) {
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
}

// Function to encrypt data
async function encryptPackage(key, data) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const encryptionTimestamp = performance.now().toString().slice(0,timestampLength);
  const additionalData = encoder.encode(encryptionTimestamp);
  console.log("Encryption Timestamp :", encryptionTimestamp);
  console.log("Encoded data :", encodedData);
  /* incrementIV(iv);
  localStorage.setItem("iv", iv.toBase64()); */
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: additionalData
    },
    key,
    encodedData,
  );
  const ivArray = new Uint8Array(iv);
  console.log("ivArray :", ivArray);
  const additionalDataArray = new Uint8Array(additionalData);
  console.log("Additional Data :", additionalData);
  const ciphertextArray = new Uint8Array(ciphertext);
  console.log("ciphertextArray :", ciphertextArray);
  const package = new Uint8Array(saltLength + timestampLength + ivLength + ciphertextArray.length);
  package.set(salt, 0);
  package.set(additionalDataArray, saltLength);
  package.set(ivArray, saltLength + timestampLength);
  package.set(ciphertextArray, saltLength + timestampLength + ivLength);
  console.log("package :", package);
  const package64 = package.toBase64();
  console.log("package64 :", package64);
  return { package64 };
}

async function decryptPackage(password, package) {
  // Decoding
  const packageToBytes = Uint8Array.fromBase64(package);
  const receivedSaltArray = packageToBytes.slice(0, saltLength);
  const receivedTimestampArray = packageToBytes.slice(saltLength, saltLength + timestampLength);
  const receivedTimestamp = new TextDecoder().decode(receivedTimestampArray);
  const receivedIvArray = packageToBytes.slice(saltLength + timestampLength, saltLength + timestampLength + ivLength);
  const receivedCiphertextArray = packageToBytes.slice(saltLength + timestampLength + ivLength);
  const rawPassword = new TextEncoder().encode(password);
  console.log("receivedSaltArray :", receivedSaltArray);
  console.log("receivedTimestamp :", receivedTimestamp);
  console.log("receivedIvArray :", receivedIvArray);
  console.log("receivedCiphertextArray :", receivedCiphertextArray);
  console.log("Raw password :", rawPassword);
  // Derive key
  const receiverBaseKey = await importBaseKey(rawPassword);
  const receiverSecretKey = await deriveSecretKey(receiverBaseKey, receivedSaltArray);
  console.log(typeof receiverBaseKey," Receiver base key:", receiverBaseKey);
  console.log(typeof receiverSecretKey," Receiver secret key:", receiverSecretKey);
  try {
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: receivedIvArray,
      additionalData: receivedTimestampArray
    },
    receiverSecretKey,
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

initializeStorage();

(async () => {
  // Sender side
  const baseKey = await window.crypto.subtle.importKey("raw", rawPassword, "PBKDF2", false, ["deriveKey"]);
  console.log(typeof baseKey," Base key:", baseKey);
  const data = "This is a secret message";
  const secretKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
  const { package64 } = await encryptPackage(secretKey, data);
  // Receiver side
  try {
    const decryptedData = await decryptPackage(password, package64);
    console.log("Decrypted message:", decryptedData.message);
    console.log("Timestamp:", decryptedData.receivedTimestamp);
  } catch (e) {
    console.log("Decryption failed with error: ", e);
    return;
  }

  const myKey = await getKey();
  console.log(typeof myKey, "My key is: ", myKey);
  const myBaseKey = await window.crypto.subtle.importKey("raw", rawPassword, "PBKDF2", false, ["deriveKey"]);
  console.log(typeof myBaseKey," Base key:", myBaseKey);
  const mysecretKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    myBaseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
  const exportedMyKey = await window.crypto.subtle.exportKey("raw", mysecretKey);
  console.log(typeof exportedMyKey, "My exported key is: ", exportedMyKey);
  const exportedMyKeyBuffer = new Uint8Array(exportedMyKey);
  console.log(typeof exportedMyKeyBuffer, "My key buffer is: ", exportedMyKeyBuffer);
  const exportedMyKeyBase64 = localStorage.getItem("key");
  console.log(typeof exportedMyKeyBase64, "My exported key: ", exportedMyKeyBase64);
  const exportedMyKeyBufferFromStorage = Uint8Array.fromBase64(exportedMyKeyBase64);
  console.log(typeof exportedMyKeyBufferFromStorage, "My key buffer from storage is: ", exportedMyKeyBufferFromStorage);
  // Decrypt the stored key
  const myDecryptBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    mysecretKey,
    exportedMyKeyBufferFromStorage,
  );
  console.log(typeof myDecryptBuffer, "My decrypted key buffer is: ", myDecryptBuffer);
  const decryptedKey = await window.crypto.subtle.importKey(
    "raw",
    myDecryptBuffer,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"],
  );
  console.log(typeof decryptedKey, "Decrypted Key is: ", decryptedKey);
  const exportedDecryptedMyKey = await window.crypto.subtle.exportKey("raw", decryptedKey);
  console.log(typeof exportedDecryptedMyKey, "My exported key is: ", exportedDecryptedMyKey);
  const myDecryptedKeyBuffer = new Uint8Array(exportedDecryptedMyKey);
  console.log(typeof myDecryptedKeyBuffer, "Decrypted Key Buffer is: ", myDecryptedKeyBuffer);
  const myKeyBase64 = myDecryptedKeyBuffer.toBase64();
  console.log(typeof myKeyBase64, "My key base64 is: ", myKeyBase64);

  // Encrypt the decrypted key again to veryfy my sanity
/*   const encryptedSecretKey1 = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    secretKey,
    myDecryptedKeyBuffer,
  );
  console.log(typeof encryptedSecretKey1, "Encrypted secret key is: ", encryptedSecretKey1);
  const encryptedSecretKeyBuffer1 = new Uint8Array(encryptedSecretKey1);
  console.log(typeof encryptedSecretKeyBuffer1, "Exported encrypted key buffer is: ", encryptedSecretKeyBuffer1);
  const encryptedSecretKey641 = encryptedSecretKeyBuffer1.toBase64();
  console.log(typeof encryptedSecretKey641, "Exported encrypted key is: ", encryptedSecretKey641); */

  /* const end = performance.now();
  console.log(end - start, " ms"); */
})();
