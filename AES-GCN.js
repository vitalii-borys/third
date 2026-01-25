// Form initial initialisation vector filled with zeros
var iv = (new Uint8Array(12).fill(0));
console.log("Initial iv :", iv);

// Function to increment the IV
function incrementIV(buffer) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    buffer[i]++;
    if (buffer[i] !== 0) {
      break;
    }
  }
}

// Generate secret key
async function generateKey() {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
}

// Function to encrypt data
async function encrypt(key, data) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  incrementIV(iv);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encodedData,
  );
  const ivArray = new Uint8Array(iv);
  console.log("ivArray :", ivArray);
  const ciphertextArray = new Uint8Array(ciphertext);
  console.log("ciphertextArray :", ciphertextArray);
  const package = new Uint8Array(ivArray.length + ciphertextArray.length);
  package.set(ivArray, 0);
  package.set(ciphertextArray, ivArray.length);
  console.log("package :", package);
  const package64 = package.toBase64();
  console.log("package64 :", package64);  
  return { package64 };
}

async function decrypt(key, receiverPackage64) {
  console.log("receivedPackage64 :", receiverPackage64);
  const packageToBytes = Uint8Array.fromBase64(receiverPackage64);
  const receivedIvArray = packageToBytes.slice(0, 12);
  const receivedCiphertextArray = packageToBytes.slice(12);
  console.log("receivedCiphertextArray :", receivedCiphertextArray);
  console.log("receivedIvArray :", receivedIvArray);
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: receivedIvArray,
    },
    key,
    receivedCiphertextArray,
  );

  return new TextDecoder().decode(decryptedBuffer);
}

(async () => {
  const key = await generateKey();
  const data = "This is a secret message";

  const { package64 } = await encrypt(key, data);
  const decrypted = await decrypt(key, package64);

  console.log("Decrypted message:", decrypted);
})();
