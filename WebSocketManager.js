export class WebSocketManager {
    
    username;

    constructor(url, callbacks) {
        this.callbacks = callbacks;
        this.ws = null;
        this.websocketServerLocation = url;
        this.forceClose = false;
        this.reconnectionAttempts = 0;
        this.maxReconnectInterval = 60000;
        this.pendingRequests = new Map();
    }

    connect() {
        this.forceClose = false;
        this.ws = new WebSocket(this.websocketServerLocation);

        this.ws.onopen = async(event) => {
            console.log("Connected to server");
            this.callbacks.setFormVisibility(event);
            const keyString = sessionStorage.getItem("wrappingKey");
            if (keyString !== null) {
                this.username = this.callbacks.getUsername();
                this.callbacks.loadCrypto(null, true);
                try {
                    if (this.username !== undefined) {
                        const messageJSON = JSON.stringify( {messageType: "challenge", username: this.username} );
                        this.ws.send(messageJSON);
                        //this.callbacks.setFormVisibility(event);
                    }
                } catch(err) {
                    console.log(err);
                }
                setTimeout(() => {
                    this.callbacks.clearInputs();
                }, 100);
            }
            this.reconnectionAttempts = 0;
        }

        this.ws.onclose = () => {
            if (this.forceClose) {
                console.log("Disconnected manually. Stopping reconnection.");
                return;
            }
            this.callbacks.handleCloseCase();
            this.reconnectionAttempts++;
            const baseWait = Math.min(this.maxReconnectInterval, 3000 * Math.pow(2, this.reconnectionAttempts - 1));
            const jitter = Math.random() * (baseWait * 0.25);
            const reconnectInterval = baseWait + jitter;
            console.log("Connection closed. Reconnecting after", reconnectInterval, "ms", this.ws.readyState);
            setTimeout(() => {
                if (!this.forceClose) {
                    this.connect();
                }
            }, reconnectInterval);
            this.ws.onclose = null;
        }

        this.ws.onmessage = async(message) => {
            this.callbacks.onMessageReceived(message);
        }
        
        this.ws.onerror = () => {
            console.log("Error. Ready state:", this.ws.readyState);
            this.ws.close();
            this.ws.onerror = null;
        }
    }

    resolvePublicKeyRequest(messageData) {
        const result = this.pendingRequests.get(messageData.username);
        if (result) {
            result(messageData.publicKey);
            this.pendingRequests.delete(messageData.username);
        }
    }

    async registerUser(username) {
        this.username = username; 
        const serverKeyBuffer = await this.callbacks.serverPublicKey();
        const encodedServerPublicKey = new Uint8Array(serverKeyBuffer).toBase64();
        const groupKey = await this.callbacks.getEncryptedGroupKeysForContacts();
        const myPublicKey = this.callbacks.getPublicKeyString();
        const messageJSON = JSON.stringify( {messageType: "register", username: username, serverPublicKey: encodedServerPublicKey, myGroupKey: groupKey, userPublicKey: myPublicKey });
        this.ws.send(messageJSON);
        console.log(messageJSON, "sent to server");
    }
    
    async getUserPublicKey(username) {
        return new Promise((resolve, reject) => {
            const messageJSON = JSON.stringify( {messageType: "getUserPublicKey", username: username} );
            this.pendingRequests.set(username, resolve);
            this.ws.send(messageJSON);
            console.log(messageJSON, "sent to server");
        });
    }
    
    disconnect() {
        this.forceClose = true;
        if (this.ws) {
            this.ws.close();
        }
    }
}