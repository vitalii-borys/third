let supportsBase64 = typeof Uint8Array.prototype.toBase64 === 'function';
supportsBase64 = false;
/* const el = document.createElement('div');
el.textContent = supportsBase64;
el.style.backgroundColor = 'red';
el.style.fontSize = '30px';
document.body.appendChild(el); */
function toBase64(uint8Array) {
  return supportsBase64 
    ? uint8Array.toBase64()
    : btoa(String.fromCharCode(...uint8Array));
}

function fromBase64(base64) {
  return supportsBase64
    ? Uint8Array.fromBase64(base64)
    : Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export class StorageManager {
    
    constructor() {
        this.ivLength = 12;
        this.saltLength = 16;
    }

    getUsername() {
        const username = localStorage.getItem("username");
        console.log(username, "is in local storage");
        return username;
    }

    setUsername(currentUsername) {
        localStorage.setItem("username", currentUsername);
        console.log(currentUsername, "written to local storage");
    }

    getOrCreateWrappingIv() {
        let wrappingIv;
        if (localStorage.getItem("wrappingIv") !== null) {
            wrappingIv = /* Uint8Array. */fromBase64(localStorage.getItem("wrappingIv"));
            //console.log("WrappingIv from local storage is: ", wrappingIv);
        } else {
            wrappingIv = crypto.getRandomValues(new Uint8Array(this.ivLength));
            localStorage.setItem("wrappingIv", /* wrappingIv. */toBase64(wrappingIv));
            //console.log("WrappingIv ", wrappingIv, " stored in local storage: ", wrappingIv);
        }
        return wrappingIv;
    }

    getOrCreateMessageIv() {
        let messageIv;
        if (localStorage.getItem("messageIv") !== null) {
            messageIv = /* Uint8Array. */fromBase64(localStorage.getItem("messageIv"));
            //console.log("MessageIv from local storage: ", messageIv);
        } else {
            //console.log("No messageIv in local storage");
            const messageIvStart = crypto.getRandomValues(new Uint8Array(this.ivLength - 4));
            const messageIvEnd = new Uint8Array(4).fill(0);
            messageIv = new Uint8Array(this.ivLength);
            messageIv.set(messageIvStart, 0);
            messageIv.set(messageIvEnd, messageIvStart.length);
            localStorage.setItem("messageIv", /* messageIv. */toBase64(messageIv));
            //console.log("messageIv ", messageIv, " stored in local storage.");
        }
        return messageIv;
    }
    
    saveMessageIv(ivBuffer) {
        localStorage.setItem("messageIv", /* ivBuffer. */toBase64(ivBuffer));
        //console.log("messageIv", ivBuffer, "stored in local storage.");
    }

    getOrCreateSalt() {
        let salt;
        if (localStorage.getItem("salt") !== null) {
            salt = /* Uint8Array. */fromBase64(localStorage.getItem("salt"));
            //console.log("Salt from local storage: ", salt);
        } else {
            salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
            //console.log("Salt :", salt);
            var saltString = /* salt. */toBase64(salt);
            localStorage.setItem("salt", saltString);
            //console.log("Salt :", saltString, " stored in local storage.");
        }
        return salt;
    }

    getEncryptedWrappedKey() {
        if (localStorage.getItem("encryptedWrappedKey") !== null) {
            const keyBuffer = /* Uint8Array. */fromBase64(localStorage.getItem("encryptedWrappedKey"));
            //console.log("Wrapped key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
            //console.log("No wrapped key in local storage is");
            return null;
        }
    }

    saveEncryptedWrappedKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("encryptedWrappedKey", keyString);
        //console.log("Encrypted wrapped key: ", keyString, " written to local storage.");
    }
    
    getEncryptedSessionKey() {
        if (localStorage.getItem("encryptedSessionKey") !== null) {
            const keyBuffer = /* Uint8Array. */fromBase64(localStorage.getItem("encryptedSessionKey"));
            //console.log("Session key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
            //console.log("No session key in local storage");
            return null;
        }
    }
    
    saveEncryptedSessionKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("encryptedSessionKey", keyString);
        //console.log("Encrypten session key: ", keyString, " written to local storage.");
    }
    
    getPublicKeyString() {
        //let keyBuffer;
        if (localStorage.getItem("publicKey") !== null) {
            //keyBuffer = Uint8Array.fromBase64(localStorage.getItem("publicKey"));
            //console.log("Public key buffer from local storage is: ", keyBuffer);
            return localStorage.getItem("publicKey");
        } else {
            return null;
        }
    }
    
    savePublicKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("publicKey", keyString);
        //console.log("Public key: ", keyString, " written to local storage.");
    }
    
    getEncryptedPrivateKey() {
        let keyBuffer;
        if (localStorage.getItem("encryptedPrivateKey") !== null) {
            keyBuffer = /* Uint8Array. */fromBase64(localStorage.getItem("encryptedPrivateKey"));
            //console.log("Private key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
             return null;
        }
    }
    
    saveEncryptedPrivateKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("encryptedPrivateKey", keyString);
        //console.log("Encrypten private key: ", keyString, " written to local storage.");
    }
    
    getServerPublicKey() {
        if (localStorage.getItem("serverPublicKey") !== null) {
            const keyBuffer = /* Uint8Array. */fromBase64(localStorage.getItem("serverPublicKey"));
            //console.log("Server public key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
            return null;
        }
    }
    
    saveServerPublicKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("serverPublicKey", keyString);
        //console.log("Server public key: ", keyString, " written to local storage.");
    }
    
    getEncryptedServerPrivateKey() {
        let keyBuffer;
        if (localStorage.getItem("encryptedServerPrivateKey") !== null) {
            keyBuffer = /* Uint8Array. */fromBase64(localStorage.getItem("encryptedServerPrivateKey")); 
            //console.log("Encrypted server private key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
             return null;
        }
    }
    
    saveEncryptedServerPrivateKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        localStorage.setItem("encryptedServerPrivateKey", keyString);
        //console.log("Encrypted server private key: ", keyString, " written to local storage.");
    }
    
    getSessionWrappingKey() {
        let keyBuffer;
        if (sessionStorage.getItem("wrappingKey") !== null) {
            keyBuffer = /* Uint8Array. */fromBase64(sessionStorage.getItem("wrappingKey"));
            //console.log("Session key buffer from local storage is: ", keyBuffer);
            return keyBuffer;
        } else {
            //console.log("No session key in local storage");
            return null;
        }
    }
    
    saveSessionWrappingKey(key) {
        const keyString = /* new Uint8Array(key). */toBase64(new Uint8Array(key));
        sessionStorage.setItem("wrappingKey", keyString);
        //console.log("Session key: ", keyString, " written to local storage.");
    }

    getPackages() {
        const encryptedPackages = JSON.parse(localStorage.getItem("encryptedPackages"));
        //console.log("Encrypted packages from local storage: ", this.#encryptedPackages);
        return encryptedPackages;
    }

    savePackages(packages) {
        localStorage.setItem("encryptedPackages", JSON.stringify(packages));
    }

    static isAvailable(type) {
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
    
    getBackupData () {
        if (StorageManager.isAvailable("localStorage")) {
            const backupJSON = {
                "encryptedPackages": this.getPackages(),
                "encryptedPrivateKey": localStorage.getItem("encryptedPrivateKey"),
                "encryptedServerPrivateKey": localStorage.getItem("encryptedServerPrivateKey"),
                "encryptedSessionKey": localStorage.getItem("encryptedSessionKey"),
                "encryptedWrappedKey": localStorage.getItem("encryptedWrappedKey"),
                "messageIv": localStorage.getItem("messageIv"),
                "publicKey": localStorage.getItem("publicKey"),
                "salt": localStorage.getItem("salt"),
                "serverPublicKey": localStorage.getItem("serverPublicKey"),
                "username": localStorage.getItem("username"),
                "wrappingIv": localStorage.getItem("wrappingIv")
            }
            return backupJSON;
        } else {
            //console.log("Local storage is not available.");
            return;
        }
    }

    setBackupData(file) {
        let importedBackup;
            const reader = new FileReader();
            reader.onload = () => {
                importedBackup = JSON.parse(reader.result);
                console.log("importedBackup", importedBackup);
                localStorage.setItem("encryptedPackages", JSON.stringify(importedBackup.encryptedPackages));
                localStorage.setItem("encryptedPrivateKey", importedBackup.encryptedPrivateKey);
                localStorage.setItem("encryptedServerPrivateKey", importedBackup.encryptedServerPrivateKey);
                localStorage.setItem("encryptedSessionKey", importedBackup.encryptedSessionKey);
                localStorage.setItem("encryptedWrappedKey", importedBackup.encryptedWrappedKey);
                this.getOrCreateMessageIv();
                localStorage.setItem("publicKey", importedBackup.publicKey);
                localStorage.setItem("salt", importedBackup.salt);
                localStorage.setItem("serverPublicKey", importedBackup.serverPublicKey);
                localStorage.setItem("username", importedBackup.username);
                localStorage.setItem("wrappingIv", importedBackup.wrappingIv);
                window.location.reload();
            };
        reader.readAsText(file);
    }
}