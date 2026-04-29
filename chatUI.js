export class ChatUI {
    username;
    #role;
    timeoutID;
    usernameAvailable;
    currentGroupID = null;
    currentGroupKey;
    conversationKeys = new Map();
    conversationMessages = new Map();

    constructor (callbacks) {
        this.callbacks = callbacks;
        this.ivLength = 12;
        this.passwordCorrect;
        this.userMessages = document.getElementById('userMessages');
        this.contactDiv = document.getElementById("contactDiv");
        this.userInput = document.getElementById('user_input');
        this.saveButton = document.getElementById('saveButton');
        this.backupButton = document.getElementById('backupButton');
        this.uploadBackupButton = document.getElementById('uploadBackupButton');
        this.fileUpload = document.getElementById('fileUpload');
        this.contactControls = document.getElementById("contactControls");
        this.contactButton = document.getElementById('contactButton');
        this.logInForm = document.getElementById('logInForm');
        this.registrationForm = document.getElementById('registrationForm');
        this.loginUsernameInput = document.getElementById('loginUsernameInput');
        this.loginPasswordInput = document.getElementById('loginPasswordInput');
        this.registerUsernameInput = document.getElementById('registerUsernameInput');
        this.loginButton = document.getElementById('loginButton');
        this.registrationSignupButton = document.getElementById('registrationSignupButton');
        this.loginUsernameInputLabel = document.getElementById('loginUsernameInputLabel');
        this.loginPasswordInputLabel = document.getElementById('loginPasswordInputLabel');
        this.registerPasswordInput = document.getElementById('registerPasswordInput');
        this.registerPasswordInputConfirm = document.getElementById('registerPasswordInputConfirm');
        this.registerUsernameInputLabel = document.getElementById('registerUsernameInputLabel');
        this.registerPasswordInputLabel = document.getElementById('registerPasswordInputLabel');
        this.registerPasswordInputConfirmLabel = document.getElementById('registerPasswordInputConfirmLabel');
        this.logoutButton = document.getElementById('logout');
        this.stayLoggedIn = document.getElementById('stayLoggedIn');
        this.welcome = document.getElementById('welcome');
        this.chatDiv = document.getElementById('chatDiv');
        this.backupControls = document.getElementById('backupControls');
        this.contactContainer = document.getElementById('contactContainer');
        this.connectionTitle = document.getElementById("connectionTitle");

        this.userInput.focus();
        
        this.userInput.addEventListener("input", (event) => {
            this.userInput.style.height = "auto";;
            this.userInput.style.height = this.userInput.scrollHeight + "px";
            this.scrollToBottom();
        });

        this.registerPasswordInputConfirm.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') {
                this.registrationSignupButton.click();
            }
        })

        this.registerPasswordInputConfirm.addEventListener('input', () => {
            clearTimeout(this.timeoutID);
            this.timeoutID = setTimeout(() => {
                if (this.registerPasswordInputConfirm.value.length === 0) {
                    this.passwordCorrect = null;
                    this.registerPasswordInputConfirmLabel.textContent = 'Write password';
                    this.registerPasswordInputConfirmLabel.style.color = 'black';
                    this.registerPasswordInputConfirm.style.backgroundColor = 'white';
                } else if (this.registerPasswordInputConfirm.value !== this.registerPasswordInput.value) {
                    this.passwordCorrect = false;
                    this.registerPasswordInputConfirmLabel.textContent = "Passwords don't match";
                    this.registerPasswordInputConfirm.style.backgroundColor = 'pink';
                } else {
                    this.passwordCorrect = true;
                    this.registerPasswordInputConfirmLabel.textContent = 'Password confirmed';
                    this.registerPasswordInputConfirm.style.backgroundColor = 'lightgreen';
                }
            }, 100);
        });

        this.registerPasswordInput.addEventListener('input', () => {
            clearTimeout(this.timeoutID);
            this.timeoutID = setTimeout(() => {
                if (this.registerPasswordInput.value.length === 0) {
                    this.registerPasswordInputLabel.textContent = 'Write password';
                    this.registerPasswordInputLabel.style.color = 'black';
                    this.registerPasswordInput.style.backgroundColor = 'white';
                } else if (this.registerPasswordInput.value.length < 6) {
                    this.registerPasswordInputLabel.textContent = '6 charachters minimum';
                    this.registerPasswordInput.style.backgroundColor = 'pink';
                } else {
                this.registerPasswordInputLabel.textContent = 'Password is good';
                this.registerPasswordInput.style.backgroundColor = 'lightgreen';
                }
            }, 100);
        });

        this.registerUsernameInput.addEventListener('input', () => {
        clearTimeout(this.timeoutID);
        this.timeoutID = setTimeout(() => {
            if (this.registerUsernameInput.value.length === 0) {
                this.registerUsernameInputLabel.textContent = 'Write username';
                this.registerUsernameInputLabel.style.color = 'black';
                this.registerUsernameInput.style.backgroundColor = 'white';
                return;
            } else if (this.registerUsernameInput.value.length < 3) {
                this.registerUsernameInput.style.backgroundColor = 'pink';
            } else {
                this.registerUsernameInput.style.backgroundColor = 'white';
            }
            const messageJSON = JSON.stringify({ messageType: "checkUsername", username: this.registerUsernameInput.value });
            this.callbacks.wsSend(messageJSON);
            console.log(messageJSON, "sent to server");
        }, 100);
        });

        this.loginPasswordInput.addEventListener('keypress', (event) => {
            if (this.loginUsernameInput.value.length < 3 && event.key === "Enter") {
                this.loginButton.click();
            }
        });

        this.loginPasswordInput.addEventListener('input', () => {
        clearTimeout(this.timeoutID);
        this.timeoutID = setTimeout(() => {
            if (this.loginPasswordInput.value.length === 0) {
                this.loginPasswordInputLabel.textContent = 'Password';
                this.loginPasswordInputLabel.style.color = 'black';
                this.loginPasswordInput.style.backgroundColor = 'white';
            } else if (this.loginPasswordInput.value.length < 6) {
                this.loginPasswordInput.style.backgroundColor = 'pink';
            } else {
                this.loginPasswordInput.style.backgroundColor = 'white';
            }
        }, 100);
        });

        this.loginUsernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
            }
        });

        this.loginUsernameInput.addEventListener('input', () => {
        clearTimeout(this.timeoutID);
        this.timeoutID = setTimeout(() => {
            if (this.loginUsernameInput.value.length === 0) {
                this.loginUsernameInputLabel.textContent = 'Username';
                this.loginUsernameInputLabel.style.color = 'black';
                this.loginUsernameInput.style.backgroundColor = 'white';
                return;
            } else if (this.loginUsernameInput.value.length < 3) {
                this.loginUsernameInput.style.backgroundColor = 'pink';
            } else {
                this.loginUsernameInputLabel.textContent = "Username";
                this.loginUsernameInput.style.backgroundColor = 'white';
            }
        }, 100);
        });

        this.registrationSignupButton.addEventListener('click', async(e) => {
            console.log("usernameAvailable & passwordCorrect", this.usernameAvailable, this.passwordCorrect);
            if (this.usernameAvailable && this.passwordCorrect) {
                console.log("All data input is correct. Trying to register.");
                e.preventDefault();
                const newPromise = new Promise((resolve) => {
                    resolve (this.callbacks.loadCrypto(registerPasswordInput.value, false));
                });
                newPromise.then(() => {
                    this.callbacks.setUsername(this.registerUsernameInput.value);
                    this.callbacks.startRegistration(this.registerUsernameInput.value);
                    this.backupButton.disabled = false;
                    this.saveButton.disabled = false;
                    this.loginUsernameInput.value = "";
                    this.loginPasswordInput.value = "";
                    this.registerPasswordInput.value = "";
                    this.registerPasswordInputConfirm.value = "";
                });
            }
        });

        this.logInForm.addEventListener('submit', async(e) => {
            e.preventDefault();
            if (this.loginUsernameInput.value.length > 2 && this.loginPasswordInput.value.length > 5) {
                this.username = this.loginUsernameInput.value;
                let result;
                const newPromise = new Promise((resolve) => {
                    resolve (this.callbacks.loadCrypto(this.loginPasswordInput.value, this.stayLoggedIn.checked));
                });
                newPromise.then(() => {
                    const messageJSON = JSON.stringify( {messageType: "challenge", username: this.loginUsernameInput.value });
                    this.callbacks.wsSend(messageJSON);
                    setTimeout(() => {
                        this.registrationForm.style.display = "none";
                        this.backupButton.disabled = false;
                        this.saveButton.disabled = false;
                        this.loginUsernameInput.value = "";
                        this.loginPasswordInput.value = "";
                        this.registerUsernameInput.value = "";
                        this.registerPasswordInput.value = "";
                        this.registerPasswordInputConfirm.value = "";
                    }, 500);
                    console.log("Login attempt");
                });
            } else {
                return;
            }
        });

        this.logoutButton.addEventListener('click', () => {
            sessionStorage.clear();
            window.location.reload();
        });

        this.userInput.addEventListener("keypress", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                this.saveButton.click();
            }
        });

        this.contactButton.addEventListener('click', async () => {
            if (document.getElementById('alertDiv')) {
                document.getElementById('alertDiv').remove();
            }
            const contactInputDiv = document.getElementById('contactInputDiv');
            if (contactInputDiv) {
                return;
            } else {
                const contactInputDiv = document.createElement('div');
                contactInputDiv.id = "contactInputDiv";
                this.contactControls.appendChild(contactInputDiv);
                const contactInput = document.createElement('input');
                contactInput.id = "contactInput";
                contactInput.autocomplete = 'off';
                const addContactButton = document.createElement('button');
                addContactButton.id = "addContactButton";
                addContactButton.textContent = "Add";
                contactInputDiv.appendChild(contactInput);
                contactInputDiv.appendChild(addContactButton);
                contactInput.focus();
                addContactButton.addEventListener('click', async () => {
                    const newContact = contactInput.value;
                    if (newContact === null || newContact.length === 0) {
                        console.log("Aborted");
                        throw new Error("No contact provided");
                    }
                    const publicKey = await this.callbacks.getUserPublicKey(newContact);
                    console.log("publicKey from server", publicKey)
                    const encryptedKeys = await this.callbacks.getEncryptedGroupKeysForContacts(publicKey);
                    console.log("encryptedKeys", encryptedKeys)
                    const messageJSON = JSON.stringify( {
                        username: this.callbacks.getUsername(),
                        messageType: "addGroupConversation",
                        myGroupKey: encryptedKeys.myEncryptedGroupKeyString,
                        arrayOfContacts: [{username: newContact, groupKey: encryptedKeys.encryptedGroupKeyString}]
                    });
                    this.callbacks.wsSend(messageJSON);
                    console.log(messageJSON, "sent to server");
                });
                contactInput.addEventListener('keydown', (event) => {
                    if (event.key === "Enter") {
                        addContactButton.click();
                    }
                });
                setTimeout(() => {
                    document.addEventListener('click', (event) => {
                        if (document.getElementById('contactControls').contains(event.target)) {
                            return;
                        } else {
                            if (document.getElementById('alertDiv')) {
                                document.getElementById('alertDiv').remove();
                            }
                            contactInputDiv.remove();
                        }
                    },);
                }, 5);
            }
        });

        this.backupButton.disabled = true;
        this.saveButton.disabled = true;

        this.saveButton.addEventListener('click', async (e) => {
            e.preventDefault();
            this.currentGroupID = this.getCurrentGroup();
            if (!this.currentGroupID) {
                this.showAlert("No conversation selected!");
                return;
            }
            this.saveButton.disabled = true;
            const data = this.userInput.value;
            const packageData = await this.callbacks.encryptMessage(this.currentGroupKey, data);
            console.log("packageData is", packageData);
            const messageJSON = JSON.stringify( {
                messageText: packageData,
                messageType: "message",
                username: this.callbacks.getUsername(),
                conversationID: this.currentGroupID
            });
            //const enryptedKeys = await this.callbacks.getEncryptedKeysForContacts();
            this.callbacks.wsSend(messageJSON);
            console.log(messageJSON);
            this.saveButton.disabled = false;
            this.userInput.value = "";
            this.userInput.style.height = "2rem";
        });

        this.backupButton.addEventListener('click', async () => {
            this.backupButton.disabled = true;
            const backupData = this.callbacks.getBackup();
            console.log(typeof backupData, backupData);
            const packages = JSON.stringify(backupData);
            const packagesBlob = new Blob([packages], { type: "application/json" });
            const backupURL = URL.createObjectURL(packagesBlob);
            this.backupButton.disabled = false;
            const backupLink = document.createElement('a');
            backupLink.textContent = "Download Backup";
            backupLink.target = "_blank";
            backupLink.rel = "noopener noreferrer";
            backupLink.href = backupURL;
            backupLink.download = "Backup.json";
            document.body.appendChild(backupLink);
            backupLink.style.display = 'none';
            backupLink.click();
            setTimeout(() => {
                URL.revokeObjectURL(backupURL);
                document.body.removeChild(backupLink);
            }, 50);
        });

        this.uploadBackupButton.addEventListener("click", () => {
            const file = fileUpload.files[0];
            this.callbacks.setBackup(file);
        });

        this.days = ['Нд', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'];
        this.months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    }
    
    scrollToBottom () {
        requestAnimationFrame(() => {
            this.userMessages.scrollTop = this.userMessages.scrollHeight;
        });
    }

    getCurrentGroup = () => {
        return this.currentGroupID;
    }

    showAlert(text) {
        const alertWindow = document.createElement("div");
        alertWindow.classList = "alertWindow";
        alertWindow.textContent = text;
        document.body.appendChild(alertWindow);
        setTimeout(() => {
            alertWindow.classList.add("visible");
        }, 0);
        setTimeout(() => {
            alertWindow.classList.remove("visible");
        }, 3500);
        setTimeout(() => {
            document.body.removeChild(alertWindow);
        }, 4000);
    }

    async addConversation(conversation) {
        console.log("conversationID is", conversation.conversationID, "conversation.participants is", conversation.participants, "group key is", conversation.groupKey.slice(0, 4));
        const currentMessages = this.conversationMessages.get(conversation.conversationID);
        const groupKey = await this.callbacks.decryptGroupKey(conversation.groupKey);
        this.conversationKeys.set(conversation.conversationID, groupKey);
        const newConversationDiv = document.createElement('div');
        newConversationDiv.classList = "conversationDiv";
        let chatDescription = "";
        conversation.participants.forEach(participant => {
            chatDescription += participant.username + " ";
        });
        if (conversation.participants.length === 1 && conversation.participants[0].username === this.callbacks.getUsername()) {
            newConversationDiv.textContent = "My notes";
        } else {
            newConversationDiv.textContent = chatDescription;
        }
        newConversationDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });
        newConversationDiv.addEventListener('click', async () => {
            if (this.currentGroupID === conversation.conversationID) {return;}
            this.currentGroupID = conversation.conversationID;
            this.currentGroupKey = this.conversationKeys.get(conversation.conversationID);
            const c = this.contactDiv.children;
            for (let child of c) {
                child.classList.remove("activeConversation");
                child.classList.add("conversationDiv");
            }
            newConversationDiv.classList = 'activeConversation';
            this.userMessages.innerHTML = "";
            const currentMessages = this.conversationMessages.get(conversation.conversationID) || [];
            for (const messageData of currentMessages) {
                await this.handleMessage(messageData);
            }
            /* conversation.messages.forEach(async messageData => {
                currentMessages.push({id: messageData.id, messageText: messageData.messageText, messageTime: messageData.messageTime});
                this.handleMessage(messageData);
            });
            this.conversationMessages.set(conversation.conversationID, currentMessages); */
            console.log("this.conversationMessages is", this.conversationMessages);
            this.userInput.focus();
            console.log("this.currentGroupID is", this.currentGroupID, "this.currentGroupKey is", this.currentGroupKey);
        });
        this.contactDiv.appendChild(newConversationDiv);
        if (document.getElementById('alertDiv')) {
            document.getElementById('alertDiv').remove();
        }
        if (document.getElementById('contactInputDiv')) {
            document.getElementById('contactInputDiv').remove();
        }
    }
    
    createMessageElement = (message, id, timestamp) => {
        let messageTimestamp;
        if (timestamp === undefined) {
            messageTimestamp = new Date();
        } else {
            messageTimestamp = timestamp;
        }
        const messageTime = new Date(Number(messageTimestamp));
        const formatted = `${String(messageTime.getHours()).padStart(2, 0)}:${String(messageTime.getMinutes()).padStart(2, 0)}`;
        const dayName = this.days[messageTime.getDay()];
        const messageTextEl = document.createElement('div');
        const messageDayEl = document.createElement('div');
        const messageTimeEl = document.createElement('div');
        const messageDiv = document.createElement('div');
        messageDiv.classList = "message";
        messageTextEl.classList = "messageTextEl";
        messageDayEl.classList = "messageDayEl";
        messageTimeEl.classList = "messageTimeEl";
        messageTextEl.textContent = message;
        messageDayEl.textContent = `${dayName}`;
        messageTimeEl.textContent = formatted;
        messageDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.createContextMenu(e.pageX, e.pageY, id, messageDiv, messageTimestamp);
        });
        messageDiv.append(messageTextEl, messageDayEl, messageTimeEl);
        this.userMessages.appendChild(messageDiv);
    }

    createContextMenu (x, y, messageId, divToRemove, messageTimestamp) {
        const menu = document.getElementsByClassName('contextMenu');
        if (menu[0] !== undefined) {
            menu[0].remove();
        }
        const contextMenu = document.createElement('div');
        const removeButton = document.createElement('div');
        const updateButton = document.createElement('div');
        contextMenu.classList = 'contextMenu';
        contextMenu.style.position = 'absolute';
        contextMenu.style.left = `${x + 5}px`;
        contextMenu.style.top = `${y + 5}px`;
        updateButton.textContent = 'Edit';
        updateButton.style.position = 'relative';
        updateButton.style.backgroundColor = 'white';
        removeButton.textContent = 'Delete';
        removeButton.style.position = 'relative';
        removeButton.style.backgroundColor = 'white';
        contextMenu.append(updateButton, removeButton);
        removeButton.addEventListener('mouseenter', () => {
            removeButton.style.background = "lightpink";
        });
        removeButton.addEventListener('mouseleave', () => {
            removeButton.style.background = "white";
        });
        updateButton.addEventListener('mouseenter', () => {
            updateButton.style.background = "lightblue";
        });
        updateButton.addEventListener('mouseleave', () => {
            updateButton.style.background = "white";
        });
        removeButton.addEventListener('click', () => {
            const messageJSON = JSON.stringify({ id: messageId, username: this.callbacks.getUsername(), messageType: "delete" });
            console.log(messageJSON);
            this.callbacks.wsSend(messageJSON);
            contextMenu.remove();
            divToRemove.remove();
        });
        updateButton.addEventListener('click', () => {
            const inputElement = document.createElement('textarea');
            inputElement.classList = "editMessageInput";
            console.log(divToRemove.style.fontSize);
            /* inputElement.style.all = 'inherit';
            inputElement.style.backgroundColor = 'white'; */
            console.log(divToRemove.children[0].offsetHeight);
            inputElement.value = divToRemove.children[0].innerText;
            inputElement.style.height = divToRemove.children[0].offsetHeight + 'px';
            const unUpdatedMessage = divToRemove.children[0]
            divToRemove.children[0].replaceWith(inputElement);
            console.log(inputElement.offsetHeight);
            console.log(inputElement.scrollHeight);
            inputElement.focus();

            inputElement.addEventListener('input', () => {                
                //inputElement.style.height = 'auto';
                console.log(inputElement.scrollHeight);
                inputElement.style.height = inputElement.scrollHeight + 'px'
            });

            setTimeout(() => {
                document.addEventListener('click', () => {
                inputElement.replaceWith(unUpdatedMessage);
                }, { once: true });
            }, 5);

            inputElement.addEventListener('keydown', async (e) => {
                if (e.key === 'Escape') {
                    inputElement.replaceWith(unUpdatedMessage);
                }
                if (e.key === 'Enter') {
                    const encryptedPackages = this.callbacks.getEncryptedPackages();
                    const decryptedMessageToEdit = await this.callbacks.decryptMessage(this.currentGroupKey, encryptedPackages[messageId].text);
                    const messageToEditTimestamp = decryptedMessageToEdit.receivedTimestamp;
                    const updatedDiv = document.createElement("div");
                    updatedDiv.classList = "messageTextEl";
                    let newMessage;
                    try {
                        console.log(inputElement.value, messageTimestamp);
                        newMessage = await this.callbacks.encryptMessage(this.currentGroupKey, inputElement.value, messageTimestamp);
                    } catch (e) {
                        console.log("Error", e);
                    }
                    updatedDiv.textContent = inputElement.value;
                    inputElement.replaceWith(updatedDiv);
                    const messageJSON = JSON.stringify({ id: messageId, "messageText": newMessage, username: this.callbacks.getUsername(), messageType: "update" });
                    console.log(messageJSON);
                    this.callbacks.wsSend(messageJSON);
                }
            });
            contextMenu.remove();
        });
        const closeMenu = (e) => {
            if (!removeButton.contains(e.target)) {
                contextMenu.remove();
                document.removeEventListener('click', closeMenu);
            }
        }
        setTimeout(() => {
            document.addEventListener('click', closeMenu);
        }, 5);
        document.body.append(contextMenu);
        return removeButton;
    }

    setFormVisibility(event) {
        console.log(event);
        if (event.type === "open") {
            this.connectionTitle.style.display = "none";
            const localUsername = this.callbacks.getUsername();
            if (localUsername !== null) {
                this.logInForm.style.display = "flex";
                this.loginUsernameInput.value = localUsername;
            } else {
                this.registrationForm.style.display = "flex";
                this.registerUsernameInput.focus();
            }
        } else if (event.type === "close") {
            this.connectionTitle.style.display = "flex";
        }
    }

    clearInputs() {
          //this.loginUsernameInput.value = "";
          this.loginPasswordInput.value = "";
          this.registerUsernameInput.value = "";
          this.registerPasswordInput.value = "";
          this.registerPasswordInputConfirm.value = "";
    }

    handleUsernameAvailability(messageData) {
        if (!messageData.available) {
            this.usernameAvailable = false;
            this.registerUsernameInputLabel.textContent = `Username ${messageData.username} is not available`;
            this.registerUsernameInputLabel.style.color = 'pink';
        } else {
            this.usernameAvailable = true;
            this.registerUsernameInputLabel.textContent = `Username ${messageData.username} is available`;
            this.registerUsernameInputLabel.style.color = 'lightgreen';
        }
        console.log(messageData);
    }

    handleNoUserCase(messageData) {
        console.log(messageData);
        let alertDiv = document.getElementById('alertDiv');
        if (alertDiv === null) {
            const alertDiv = document.createElement('div');
            alertDiv.textContent = messageData.messageText;
            alertDiv.id = "alertDiv";
            this.contactControls.appendChild(alertDiv);
        } else {
            const alertDiv = document.getElementById('alertDiv');
            alertDiv.textContent = messageData.messageText;
        }
    }

    handleInitialCase(messageData) {
        if (document.getElementById('alertDiv')) {
            document.getElementById('alertDiv').remove();
        }
        if (document.getElementById('contactInputDiv')) {
            document.getElementById('contactInputDiv').remove();
        }
        this.registerUsernameInput.value = "";
        this.registrationForm.style.display = "none";
        this.logInForm.style.display = "none";
        this.chatDiv.style.display = "flex";
        this.backupControls.style.display = "flex";
        this.contactContainer.style.display = "flex";

        if (messageData.userRole === "admin") {
            this.#role = "admin";
            console.log(this.#role, "is yor role");            
            const adminbutton = document.getElementById("adminButton");
            adminbutton.style.display = "flex";
            const adminTable = document.getElementById("adminTable");
            const adminTableBody = document.getElementById("adminTableBody");
            adminbutton.addEventListener('click', () => {
                if (adminbutton.textContent === "Show database") {
                    adminbutton.textContent = "Hide database";
                    adminTable.style.display = "block";
                } else {
                    adminTableBody.innerHTML = ""; // will need to change to textContent
                    adminbutton.textContent = "Show database";
                    adminTable.style.display = "none";
                }
                if (this.#role === "admin") {
                    adminTableBody.innerHTML = "";
                    let row;
                    messageData.users.forEach(user => {
                    messageData.allMessages.forEach(message => {
                        if (message.username === user.username) {
                            console.log(message.username);
                            const timestamp = new Date(message.messageTime);
                            const formattedTimestamp = `${String(timestamp.getDate())} ${String(this.months[timestamp.getMonth()])} ${String(timestamp.getHours()).padStart(2, 0)}:${String(timestamp.getMinutes()).padStart(2, 0)}`
                            row =  `<tr><th>${user.username}</th><td>${user.userRole}</td><td>${formattedTimestamp}</td></tr>`
                        }
                    });
                    adminTableBody.innerHTML += row;
                    });
                } else if (this.#role === "user") {
                    console.log("You are user");
                } else {
                    console.log("Role is not set");
                }
            });
        } else if (messageData.userRole === "user") {
            this.#role = "user";
        }
        this.userMessages.innerHTML = "";
        this.contactDiv.innerHTML = "";
        messageData.conversations.forEach(conversation => {
            const messageArray = [];
            conversation.messages.forEach(message => {
                const formattedMessage = {id: message.id, messageText: message.messageText, messageTime: message.messageTime}
                messageArray.push(formattedMessage);
            });
            this.conversationMessages.set(conversation.conversationID, messageArray);
            this.addConversation(conversation);
        });
        this.backupButton.disabled = false;
        this.saveButton.disabled = false;
        this.scrollToBottom();
        console.log("this.conversationMessages is ", typeof this.conversationMessages, this.conversationMessages);
    }

    async handleMessage(messageData) {
        console.log("messageData is", messageData);
        const decryptedMessage = await this.callbacks.decryptMessage(this.currentGroupKey, messageData.messageText);
        this.createMessageElement(decryptedMessage.message, messageData.id, decryptedMessage.receivedTimestamp);
        const encryptedPackages = this.callbacks.getEncryptedPackages();
        encryptedPackages[messageData.id] = {text: messageData.messageText};
        localStorage.setItem("encryptedPackages", JSON.stringify(encryptedPackages));
        this.scrollToBottom();
    }

    addMessageToConversation(messageData) {
        console.log("messageData is", messageData)
        const currentGroupKey = this.conversationKeys.get(messageData.conversationID);
        const currentMessages = this.conversationMessages.get(messageData.conversationID);
        const formattedMessage = {id: messageData.id, messageText: messageData.messageText, messageTime: messageData.messageTime};
        currentMessages.push(formattedMessage);
        this.conversationMessages.set(messageData.conversationID, currentMessages);
        console.log(formattedMessage, "written to conversation", messageData.conversationID);
        this.handleMessage(messageData);
    }

    handleCloseCase() {
        this.contactContainer.style.display = "none";
        this.backupControls.style.display = "none";
        this.chatDiv.style.display = "none";
        this.logInForm.style.display = "none";
        this.registrationForm.style.display = "none";
        this.connectionTitle.style.display = "flex";
    }
}