const timestampLength = 3;
//const start = performance.now();
const password = "12345678";
const saltLength = 16;
const salt = crypto.getRandomValues(new Uint8Array(saltLength));
console.log("Salt :", salt);

const rawPassword = new TextEncoder().encode(password);
console.log("Raw password data :", rawPassword);

function importSecretKey(rawKey) {
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

// Form initial initialisation vector filled with zeros
const ivLength = 12;
var iv = (new Uint8Array(ivLength).fill(0));

// Function to increment the IV
function incrementIV(buffer) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    buffer[i]++;
    if (buffer[i] !== 0) {
      break;
    }
  }
}

// Function to encrypt data
async function encrypt(key, data) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const encryptionTimestamp = performance.now().toString().slice(0,timestampLength);
  const additionalData = encoder.encode(encryptionTimestamp);
  console.log("Encryption Timestamp :", encryptionTimestamp);
  console.log("Encoded data :", encodedData);
  incrementIV(iv);
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

async function decrypt(password, package) {
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
  const receiverBaseKey = await importSecretKey(rawPassword);
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

(async () => {
  const data = "This is a secret message";
  // Sender side
  const baseKey = await importSecretKey(rawPassword);
  console.log(typeof baseKey," Base key:", baseKey);
  const secretKey = await deriveSecretKey(baseKey, salt);
  console.log(typeof secretKey," Secret key:", secretKey);
  const { package64 } = await encrypt(secretKey, data);
  // Receiver side
  try {
    const decryptedData = await decrypt(password, package64);
    console.log("Decrypted message:", decryptedData.message);
    console.log("Timestamp:", decryptedData.receivedTimestamp);
  } catch (e) {
    console.log("Decryption failed with error: ", e);
    return;
  }
  /* const end = performance.now();
  console.log(end - start, " ms"); */
})();
