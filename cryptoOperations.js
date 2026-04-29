
export class CryptoVault {
    timestampLength = 8;
    ivLength = 12;
    #messageIv;
    #serverPrivateKey;
    serverPublicKey;
    #sessionKey;
    #wrappingKey;
    #wrappingIv;
    #clientPrivateKey;
    clientPublicKey;

    constructor(callbacks) {
        this.callbacks = callbacks;
    }

    async getEncryptedGroupKeysForContacts(usernamePublicKey) {
        const groupKeyBuffer = await this.generateGroupKey();
        const keyString = new Uint8Array(groupKeyBuffer).toBase64();
        const encoder = new TextEncoder();
        const encodedGroupKey = encoder.encode(keyString);
        let encryptedGroupKeyString;
        if(usernamePublicKey !== undefined) {

            const participantPublicKeyBuffer = Uint8Array.fromBase64(usernamePublicKey);
            const participantPublicKey = await window.crypto.subtle.importKey(
                "spki",
                participantPublicKeyBuffer,
                {name: "RSA-OAEP", hash: "SHA-256"},
                true,
                ["encrypt"]
            );
            console.log("participantPublicKey", participantPublicKey);
            const encryptedGroupKeyBuffer = await window.crypto.subtle.encrypt(
                {name: "RSA-OAEP"},
                participantPublicKey,
                encodedGroupKey
            );
            encryptedGroupKeyString = new Uint8Array(encryptedGroupKeyBuffer).toBase64();
            console.log("encryptedGroupKeyString is", encryptedGroupKeyString);
        }
            
            const myEncryptedGroupKeyBuffer = await window.crypto.subtle.encrypt(
                {name: "RSA-OAEP"},
                this.clientPublicKey,
                encodedGroupKey
            );
            const myEncryptedGroupKeyString = new Uint8Array(myEncryptedGroupKeyBuffer).toBase64();
            console.log("My encryptedGroupKeyString is", myEncryptedGroupKeyString);
        if (usernamePublicKey !== undefined) {
            return {encryptedGroupKeyString, myEncryptedGroupKeyString};
        } else {
            console.log("myEncryptedGroupKeyString", myEncryptedGroupKeyString);
            return myEncryptedGroupKeyString;
        }
    }

    async decryptGroupKey(keyString) {
        const groupKeyBuffer = Uint8Array.fromBase64(keyString);
        const decryptedGroupKeyBuffer = await window.crypto.subtle.decrypt(
            {name: "RSA-OAEP"},
            this.#clientPrivateKey,
            groupKeyBuffer
        );
        const decoder = new TextDecoder;
        const decodedGroupKey = decoder.decode(decryptedGroupKeyBuffer);
        const decodedKeyBuffer = Uint8Array.fromBase64(decodedGroupKey);
        const importedKey = await window.crypto.subtle.importKey(
            "raw",
            decodedKeyBuffer,
            "AES-GCM",
            true,
            ['encrypt', 'decrypt']
        );
        return importedKey;
    }

    async generateGroupKey() {
        const generatedKey = await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"],
        );
        console.log("No group key in local storage so newely genegated random key is: ", generatedKey);
        const exportedKey = await window.crypto.subtle.exportKey("raw", generatedKey);
        return exportedKey;
    }

    async signData(data) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        let signature = await window.crypto.subtle.sign(
            "RSASSA-PKCS1-v1_5",
            this.#serverPrivateKey,
            encodedData
        );
        signature = new Uint8Array(signature).toBase64();
        return signature;
    }

    #bigintToUint8Buffer (bigInt) {
        let dataView = new DataView(new ArrayBuffer(8), 0);
        dataView.setBigUint64(0, bigInt);
        let uint8Array = new Uint8Array(dataView.buffer);
        return uint8Array;
    }

    #uint8ArrayToBigint (bigIntBuffer) {
        let dataView = new DataView(bigIntBuffer.buffer, 0);
        let myBigInt = dataView.getBigUint64(0);
        return myBigInt;
    }

    async load(userPassword, stayLoggedIn) {
        this.#messageIv = this.callbacks.getOrCreateMessageIv();
        this.#wrappingIv = this.callbacks.getOrCreateWrappingIv();
        let sessionKeyBuffer = this.callbacks.getEncryptedSessionKey();
        if (sessionKeyBuffer !== null) {
            this.#sessionKey = await this.#getKey(userPassword, stayLoggedIn);
            await this.loadKeysFromStorage(this.#wrappingIv);
        } else {
            this.#sessionKey = await this.#getKey(userPassword, stayLoggedIn);
            await this.generaTeAndStoreNewKeys(this.#wrappingIv);
        }
        if (this.#sessionKey && this.#serverPrivateKey && this.serverPublicKey && this.#clientPrivateKey && this.clientPublicKey) {
            if (stayLoggedIn) {
                const exportedWrappingKey = await window.crypto.subtle.exportKey("raw", this.#wrappingKey);
                this.callbacks.saveSessionWrappingKey(exportedWrappingKey);
            }
            return this;
        } else {
            return null;
        }
    }
  
    async encryptPackage(key, data, timestamp) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        let additionalData;
        if (timestamp !== undefined) {
            additionalData = this.#bigintToUint8Buffer(timestamp);
        } else {
            additionalData = this.#bigintToUint8Buffer(BigInt(Date.now()));
        }
        this.#incrementIv(this.#messageIv);
        console.log("Key 55 is", key);
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: this.#messageIv,
                additionalData: additionalData
            },
            key,
            //this.#sessionKey,
            encodedData,
        );
        const ciphertextArray = new Uint8Array(ciphertext);
        const packageData = new Uint8Array(this.timestampLength + this.ivLength + ciphertextArray.length);
        packageData.set(additionalData, 0);
        packageData.set(this.#messageIv, this.timestampLength);
        packageData.set(ciphertextArray, this.timestampLength + this.ivLength);
        const package64 = packageData.toBase64();
        return package64;
    }

    async decryptPackage(key, packageData) {
        const packageToBytes = Uint8Array.fromBase64(packageData);
        const receivedTimestampArray = packageToBytes.slice(0, this.timestampLength);
        const receivedTimestamp = this.#uint8ArrayToBigint(receivedTimestampArray);
        const receivedMessageIvArray = packageToBytes.slice(this.timestampLength, this.timestampLength + this.ivLength);
        const receivedCiphertextArray = packageToBytes.slice(this.timestampLength + this.ivLength);
        try {
            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: receivedMessageIvArray,
                    additionalData: receivedTimestampArray
                },
                key,
                //this.#sessionKey,
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

    async deriveWrappingKeyFromPassword(masterKey, salt, stayLoggedIn) {
        this.#wrappingKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 700000,
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
        return this.#wrappingKey;
    }

    async loadWrappingKeyFromSession() {
        const importKeyBuffer = this.callbacks.getSessionWrappingKey();
        const decryptedKey = await window.crypto.subtle.importKey(
            "raw",
            importKeyBuffer,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"],
        );
        this.#wrappingKey = decryptedKey;
    }
  
    async #getKey(userPassword, stayLoggedIn) {
        const salt = this.callbacks.getOrCreateSalt();
        var encodedPassword = new TextEncoder().encode(userPassword);
        userPassword = "";
        const masterKey = await window.crypto.subtle.importKey("raw", encodedPassword, "PBKDF2", false, ["deriveKey"]);
        encodedPassword = null;
        let storedKey = this.callbacks.getSessionWrappingKey();
        if (storedKey) {
            await this.loadWrappingKeyFromSession();
            console.log("Wrapping key from session storage is: ", this.#wrappingKey);
        } else {
            await this.deriveWrappingKeyFromPassword(masterKey, salt, stayLoggedIn);
            console.log("Wrapping key generated from password is: ", this.#wrappingKey);
        }

        const wrappedKeyBuffer = this.callbacks.getEncryptedWrappedKey();
        //console.log("wrappedKeyBuffer", wrappedKeyBuffer, "wrappingKey", this.#wrappingKey, "wrappingIv", wrappingIv)
        if (wrappedKeyBuffer !== null) {
            try {
                const decryptBuffer = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: this.#wrappingIv,
                    },
                    this.#wrappingKey,
                    wrappedKeyBuffer,
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
            console.log("No key in local storage so newely genegated random key is: ", generatedKey);
            const exportedKey = await window.crypto.subtle.exportKey("raw", generatedKey);
            console.log(typeof exportedKey, "Exported Key is: ", exportedKey);
            const encryptedWrappingKey = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: this.#wrappingIv,
                },
                this.#wrappingKey,
                new Uint8Array(exportedKey),
            );
            this.callbacks.saveEncryptedWrappedKey(encryptedWrappingKey);
            return generatedKey;
        }
    }

    async #generateKeyPair(keyPairType) {
        let keyPair = null;
        if (keyPairType === "server") {
            keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
            );
        } else if (keyPairType === "client") {      
            keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["decrypt", "encrypt"],
            );
        }
        return keyPair;
    }

    async loadKeysFromStorage() {
        const publicKeyBuffer = Uint8Array.fromBase64(this.callbacks.getPublicKeyString());
        const publicKey = await crypto.subtle.importKey(
            "spki",
            publicKeyBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256" },
            true,
            ["encrypt"]
        );
        this.clientPublicKey = publicKey;
        
        const privateKeyBuffer = this.callbacks.getEncryptedPrivateKey();
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
            {
                name: "RSA-OAEP",
                hash: "SHA-256" },
            true,
            ["decrypt"],
        );
        this.#clientPrivateKey = privateKey;
        
        const serverPublicKeyBuffer = this.callbacks.getServerPublicKey();
        const serverPublicKey = await crypto.subtle.importKey(
            "spki",
            serverPublicKeyBuffer,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256" },
            true,
            ["verify"]
        );
        this.serverPublicKey = serverPublicKey;
        
        const serverPrivateKeyBuffer = this.callbacks.getEncryptedServerPrivateKey();
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
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            true,
            ["sign"],
        );
        this.#serverPrivateKey = serverPrivateKey;
    }

    async generaTeAndStoreNewKeys() {    
        const clientKeyPair = await this.#generateKeyPair("client");
        console.log("Client Key Pair generated as:", clientKeyPair);
        const serverKeyPair = await this.#generateKeyPair("server");
        const clientPublicKey = clientKeyPair.publicKey;
        console.log("Client public key generated as:", clientPublicKey);
        const clientPrivateKey = clientKeyPair.privateKey;
        this.clientPublicKey = clientPublicKey;
        this.#clientPrivateKey = clientPrivateKey;
        console.log("No key pair in local storage so newely generated keys are: ", clientPublicKey, clientPrivateKey);
        
        const exportedPublicKey = await crypto.subtle.exportKey("spki", clientPublicKey);
        this.callbacks.savePublicKey(exportedPublicKey);
        
        const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#clientPrivateKey);
        const encryptedPrivateKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: this.#wrappingIv
            },
            this.#wrappingKey,
            exportedPrivateKey
        );
        this.callbacks.saveEncryptedPrivateKey(encryptedPrivateKey);
        
        const exportedSessionKey = await crypto.subtle.exportKey("raw", this.#sessionKey);
        console.log(exportedSessionKey);
        const encryptedSessionKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: this.#wrappingIv
            },
            this.#sessionKey,
            exportedSessionKey
        );
        this.callbacks.saveEncryptedSessionKey(encryptedSessionKey);
        
        const serverPublicKey = serverKeyPair.publicKey;
        const serverPrivateKey = serverKeyPair.privateKey;
        this.serverPublicKey = serverPublicKey;
        this.#serverPrivateKey = serverPrivateKey;
        console.log("No key pair in local storage so newely generated server keys are: ", serverPublicKey, serverPrivateKey);

        const exportedServerPublicKey = await crypto.subtle.exportKey("spki", serverPublicKey);
        this.callbacks.saveServerPublicKey(exportedServerPublicKey);
        
        const exportedSeverPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#serverPrivateKey);
        const encryptedServerPrivateKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: this.#wrappingIv
            },
            this.#wrappingKey,
            exportedSeverPrivateKey
        );
        this.callbacks.saveEncryptedServerPrivateKey(encryptedServerPrivateKey);
    }

    #incrementIv(buffer) {
        for (let i = buffer.length - 1; i >= 0; i--) {
            buffer[i]= (buffer[i] + 1) % 256;
            if (buffer[i] !== 0) {
                break;
            }
        }
    }
}