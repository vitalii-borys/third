// Data
const myString = "Привіт, світ!";
console.log(myString);
const key = "BT1";
const myEncoder = new TextEncoder();
const myDecoder = new TextDecoder();

// Encoding
const myEncodedString = myEncoder.encode(myString);
const myEncodedKey = myEncoder.encode(key);
console.log(myEncodedString);
console.log(myEncodedKey);

// Encrypting
const myEncryptedString = myEncodedString.map((byte, index) => byte ^ myEncodedKey[index % myEncodedKey.length]);
console.log(myEncryptedString);

// Decrypting
const myDecryptedString = myEncryptedString.map((byte, index) => byte ^ myEncodedKey[index % myEncodedKey.length]);
console.log(myDecryptedString);

// Decoding
const myDecodedString = myDecoder.decode(myDecryptedString);
console.log(myDecodedString);

// Output encrypted
const encryptedStringOutput = myEncryptedString.toBase64();
console.log(encryptedStringOutput);

// Back to bytes
const encryptedBytesBack = Uint8Array.fromBase64(encryptedStringOutput);
console.log(encryptedBytesBack);

// Decrypting on receiver's side
const receivedDecryptedString = encryptedBytesBack.map((byte, index) => byte ^ myEncodedKey[index % myEncodedKey.length]);
console.log(receivedDecryptedString);

// Decoding on receiver's side
const receivedDecodedString = myDecoder.decode(receivedDecryptedString);
console.log(receivedDecodedString);

var container = document.body.appendChild( document.createElement( 'div' ) );
container.id = 'container';
container.style.top = '0px';
container.style.left = '0px';

var myInput = container.appendChild( document.createElement( 'textarea' ) );
myInput.style.position = 'relative';
myInput.id = 'myInput';
myInput.style.top = '85px';
myInput.style.left = '10px';
myInput.style.fontSize = '24px';
myInput.placeholder = 'Message';

var keyInput = container.appendChild( document.createElement( 'textarea' ) );
keyInput.style.position = 'relative';
keyInput.id = 'keyInput';
keyInput.style.top = '10px';
keyInput.style.left = '10px';
keyInput.style.fontSize = '24px';
keyInput.placeholder = 'Key';

var output = container.appendChild( document.createElement( 'textarea' ) );
output.style.position = 'relative';
output.id = 'output';
output.style.top = '468px';
output.style.left = '10px';
output.style.fontSize = '24px';

var encryptButton = container.appendChild( document.createElement( 'button' ) );
encryptButton.style.position = 'relative';
encryptButton.id = 'encryptButton';
encryptButton.style.top = '350px';
encryptButton.style.left = '10px';
encryptButton.style.fontSize = '20px';
encryptButton.textContent = 'Encrypt';

var decryptButton = container.appendChild( document.createElement( 'button' ) );
decryptButton.style.position = 'relative';
decryptButton.id = 'decryptButton';
decryptButton.style.top = '365px';
decryptButton.style.left = '10px';
decryptButton.style.fontSize = '20px';
decryptButton.textContent = 'Decrypt';

encryptButton.onclick = function() {
    const message = myInput.value;
    const key = keyInput.value;
    const messageBytes = myEncoder.encode(message);
    const keyBytes = myEncoder.encode(key);
    const encryptedBytes = messageBytes.map((byte, index) => byte ^ keyBytes[index % keyBytes.length]);
    const encryptedMessageOutput = encryptedBytes.toBase64();
    console.log(encryptedMessageOutput);
    output.value = encryptedMessageOutput;
    myInput.value = '';
}

decryptButton.onclick = function() {
    const encryptedInput = myInput.value;
    const key = keyInput.value;
    const encryptedBytes = Uint8Array.fromBase64(encryptedInput);
    const keyBytes = myEncoder.encode(key);
    const decryptedBytes = encryptedBytes.map((byte, index) => byte ^ keyBytes[index % keyBytes.length]);
    const decryptedMessage = myDecoder.decode(decryptedBytes);
    console.log(decryptedMessage);
    output.value = decryptedMessage;
    myInput.value = '';
}