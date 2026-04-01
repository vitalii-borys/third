
export class CryptoVault {
    #storageManager;
    timestampLength = 8;
    ivLength = 12;
    #messageIv;
    #serverPrivateKey;
    serverPublicKey;
    #sessionKey;
    #wrappingKey;
    #clientPrivateKey;
    clientPublicKey;

    constructor(storageManager) {
        this.#storageManager = storageManager;
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
        this.#messageIv = this.#storageManager.getOrCreateMessageIv();
        const wrappingIv = this.#storageManager.getOrCreateWrappingIv();
        let sessionKey = this.#storageManager.getEncryptedSessionKey();
        if (sessionKey !== null) {
            this.#sessionKey = await this.#getKey(userPassword, stayLoggedIn);
            await this.loadKeysFromStorage(wrappingIv);
        } else {
            this.#sessionKey = await this.#getKey(userPassword, stayLoggedIn);
            await this.generaTeAndStoreNewKeys(wrappingIv);
        }
        return this;
    }
  
    async encryptPackage(data, timestamp) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        let additionalData;
        if (timestamp !== undefined) {
            additionalData = this.#bigintToUint8Buffer(timestamp);
        } else {
            additionalData = this.#bigintToUint8Buffer(BigInt(Date.now()));
        }
        this.#incrementIv(this.#messageIv);
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
        const packageData = new Uint8Array(this.timestampLength + this.ivLength + ciphertextArray.length);
        packageData.set(additionalData, 0);
        packageData.set(this.#messageIv, this.timestampLength);
        packageData.set(ciphertextArray, this.timestampLength + this.ivLength);
        const package64 = packageData.toBase64();
        return package64;
    }

    async decryptPackage(packageData) {
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

    async deriveWrappingKeyFromPassword(masterKey, salt, stayLoggedIn) {
        console.log(masterKey, salt, stayLoggedIn);
        const wrappingKey = await window.crypto.subtle.deriveKey(
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
        this.#wrappingKey = wrappingKey;
        if (stayLoggedIn) {
            const exportedWrappingKey = await window.crypto.subtle.exportKey("raw", wrappingKey);
            const wrappingKeyBuffer = new Uint8Array(exportedWrappingKey).toBase64();
            sessionStorage.setItem("wrappingKey", wrappingKeyBuffer);
            console.log("Session key is written to session storage");
        }
        return wrappingKey;
    }

    async loadWrappingKeyFromSession() {
        const importKeyBuffer = this.#storageManager.getSessionWrappingKey();
        const decryptedKey = await window.crypto.subtle.importKey(
            "raw",
            importKeyBuffer,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"],
        );
        return decryptedKey;
    }
  
    async #getKey(userPassword, stayLoggedIn) {
        const salt = this.#storageManager.getOrCreateSalt();
        const wrappingIv = this.#storageManager.getOrCreateWrappingIv();
        var encodedPassword = new TextEncoder().encode(userPassword);
        userPassword = "";
        const masterKey = await window.crypto.subtle.importKey("raw", encodedPassword, "PBKDF2", false, ["deriveKey"]);
        encodedPassword = null;
        let wrappingKey;
        let storedKey = this.#storageManager.getSessionWrappingKey();
        if (storedKey !== null) {
            wrappingKey = await this.loadWrappingKeyFromSession();
            console.log("Wrapping key from session storage is: ", wrappingKey);
        } else {
            wrappingKey = await this.deriveWrappingKeyFromPassword(masterKey, salt, stayLoggedIn);
            console.log("Newely generated wrapping key is: ", wrappingKey);
        }
        this.#wrappingKey = wrappingKey;

        const wrappedKeyBuffer = this.#storageManager.getEncryptedWrappedKey();
        if (wrappedKeyBuffer !== null) {
            try {
                const decryptBuffer = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: wrappingIv,
                    },
                    wrappingKey,
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
                    iv: wrappingIv,
                },
                wrappingKey,
                new Uint8Array(exportedKey),
            );
            this.#storageManager.saveEncryptedWrappedKey(encryptedWrappingKey);
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
            ["encrypt", "decrypt"],
            );
        }
        return keyPair;
    }

    async loadKeysFromStorage(wrappingIv) {
        const publicKeyBuffer = this.#storageManager.getPublicKey();
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
        
        const privateKeyBuffer = this.#storageManager.getEncryptedPrivateKey();
        let decryptedPrivateKey;
        try {
            decryptedPrivateKey = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: wrappingIv
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
        
        const serverPublicKeyBuffer = this.#storageManager.getServerPublicKey();
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
        
        const serverPrivateKeyBuffer = this.#storageManager.getEncryptedServerPrivateKey();
        let decryptedServerPrivateKey;
        try {
            decryptedServerPrivateKey = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: wrappingIv
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

    async generaTeAndStoreNewKeys(wrappingIv) {    
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
        this.#storageManager.savePublicKey(exportedPublicKey);
        
        const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#clientPrivateKey);
        const encryptedPrivateKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: wrappingIv
            },
            this.#wrappingKey,
            exportedPrivateKey
        );
        this.#storageManager.saveEncryptedPrivateKey(encryptedPrivateKey);
        
        const exportedSessionKey = await crypto.subtle.exportKey("raw", this.#sessionKey);
        console.log(exportedSessionKey);
        const encryptedSessionKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: wrappingIv
            },
            this.#sessionKey,
            exportedSessionKey
        );
        this.#storageManager.saveEncryptedSessionKey(encryptedSessionKey);
        
        const serverPublicKey = serverKeyPair.publicKey;
        const serverPrivateKey = serverKeyPair.privateKey;
        this.serverPublicKey = serverPublicKey;
        this.#serverPrivateKey = serverPrivateKey;
        console.log("No key pair in local storage so newely generated server keys are: ", serverPublicKey, serverPrivateKey);

        const exportedServerPublicKey = await crypto.subtle.exportKey("spki", serverPublicKey);
        this.#storageManager.saveServerPublicKey(exportedServerPublicKey);
        
        const exportedSeverPrivateKey = await crypto.subtle.exportKey("pkcs8" , this.#serverPrivateKey);
        const encryptedServerPrivateKey = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: wrappingIv
            },
            this.#wrappingKey,
            exportedSeverPrivateKey
        );
        this.#storageManager.saveEncryptedServerPrivateKey(encryptedServerPrivateKey);
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