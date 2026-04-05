export class WebSocketManager {
    
    username;

    constructor(url, callbacks) {
        this.callbacks = callbacks;
        this.ws = null;
        this.websocketServerLocation = url;
        this.forceClose = false;
        this.reconnectionAttempts = 0;
        this.maxReconnectInterval = 60000;
    }

    connect() {
        this.forceClose = false;
        this.ws = new WebSocket(this.websocketServerLocation);

        this.ws.onopen = async(event) => {
            console.log("Connected to server");
            this.callbacks.setFormVisibility(event);
            const keyString = sessionStorage.getItem("wrappingKey");
            if (keyString !== null) {
                this.username = this.callbacks.setUsername();
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
            /* const messageData = JSON.parse(message.data);
            switch(messageData.messageType) {
                case "checkUsername": {
                    this.callbacks.handleUsernameAvailability(messageData);
                }
                break;
                case "error": {
                    console.log(messageData);
                }
                break;
                case "noAuth": {
                    console.log(messageData);
                }
                break;
                case "noUser": {
                    this.callbacks.handleNoUserCase(messageData);
                }
                break;
                case "initialMessage": {
                    localStorage.setItem("username", this.username);
                    this.callbacks.handleInitialCase(messageData);
                    //this.callbacks.setFormVisibility();
                }
                break;
                case "userContact": {
                    this.callbacks.addContact(messageData);
                }
                break;
                case "auth": {
                    console.log(messageData, "in auth");
                    this.username = this.callbacks.setUsername();
                    const signatureForServer = await this.callbacks.signData(messageData.messageText);
                    const messageJSON = JSON.stringify( {messageType: "auth", messageText: signatureForServer, username: this.username });
                    this.ws.send(messageJSON);
                }
                break;
            } */
        }
        
        this.ws.onerror = () => {
            console.log("Error. Ready state:", this.ws.readyState);
            this.ws.close();
            this.ws.onerror = null;
        }
    }

    async registerUser(username) {
        this.username = username; 
        const serverKeyBuffer = await this.callbacks.serverPublicKey();
        const publicKeyBuffer = new Uint8Array(serverKeyBuffer).toBase64();
        const messageJSON = JSON.stringify( {messageType: "register", username: username, publicKey: publicKeyBuffer });
        this.ws.send(messageJSON);
        console.log(messageJSON, "sent to server");
    }
    
    disconnect() {
        this.forceClose = true;
        if (this.ws) {
        this.ws.close();
        }
    }
}