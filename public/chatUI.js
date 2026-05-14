export class ChatUI {
    username;
    #role;
    timeoutID;
    usernameAvailable;
    currentGroupID = null;
    currentGroupKey;
    conversationKeys = new Map();
    conversationMessages = new Map();
    userNameRegex = /^[a-zA-Zа-яА-Я0-9_-]{3,20}$/u;
    contactDivs = [];
    lastActiveConversation;

    constructor (callbacks) {
        this.callbacks = callbacks;
        this.ivLength = 12;
        this.passwordCorrect;
        this.userMessages = document.getElementById('userMessages');
        this.contactDiv = document.getElementById("contactDiv");
        this.userInput = document.getElementById('user_input');
        this.saveButton = document.getElementById('saveButton');
        this.backupButton = document.getElementById('backupButton');
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
        this.registrationUploadBackupButton = document.getElementById('registrationUploadBackupButton');
        this.removeData = document.getElementById('removeData');
        this.logoutButton = document.getElementById('logout');
        this.stayLoggedIn = document.getElementById('stayLoggedIn');
        this.registerStayLoggedIn = document.getElementById('registerStayLoggedIn');
        this.welcome = document.getElementById('welcome');
        this.chatDiv = document.getElementById('chatDiv');
        this.backupControls = document.getElementById('backupControls');
        this.contactContainer = document.getElementById('contactContainer');
        this.connectionTitle = document.getElementById("connectionTitle");
        this.showHideContacts = document.getElementById('showHideContacts');
        this.showHideBackup = document.getElementById('showHideBackup');

        this.removeData.addEventListener('click', () => {
            localStorage.clear();
            window.location.reload();
        });

        this.registrationUploadBackupButton.addEventListener('click', () => {
            this.fileUpload.click();
        });
        this.fileUpload.addEventListener('change', () => {
            const file = this.fileUpload.files[0];
            if (!file) {return;}
            this.callbacks.setBackup(file);
        });

        this.showHideContacts.addEventListener('click', () => {
            this.contactContainer.classList.toggle('active');
            this.backupControls.classList.remove('active');
        });

        this.showHideBackup.addEventListener('click', () => {
            this.backupControls.classList.toggle('active');
            this.contactContainer.classList.remove('active');
        });

        document.getElementById('chatDiv').addEventListener('click', () => {
            this.backupControls.classList.remove('active');
            this.contactContainer.classList.remove('active');
        });

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
            //} else if (this.registerUsernameInput.value.length < 3 || this.registerUsernameInput.value.length > 20) {
            } else if (!this.userNameRegex.test(this.registerUsernameInput.value)) {
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
            if (this.loginUsernameInput.value.length > 2 && this.loginUsernameInput.value.length < 21 && event.key === "Enter") {
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
                    resolve (this.callbacks.loadCrypto(this.registerPasswordInput.value, this.registerStayLoggedIn.checked));
                });
                newPromise.then(() => {
                    this.username = this.registerUsernameInput.value;
                    this.callbacks.setUsername(this.registerUsernameInput.value);
                    this.callbacks.startRegistration(this.registerUsernameInput.value);
                    this.backupButton.disabled = false;
                    this.saveButton.disabled = false;
                    //this.loginUsernameInput.value = "";
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
                        //this.loginUsernameInput.value = "";
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

        this.contactButton.addEventListener('click', async (event) => {
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
                this.contactDivs = document.querySelectorAll(".conversationDiv");
                contactInput.addEventListener('input', () => {
                    if (contactInput.value.length === 0) {
                        this.contactDivs?.forEach((div) => {
                            div.style.display = "flex";
                        });
                    } else {
                        this.contactDivs?.forEach((div, index) => {
                            if (index === 0) {
                                div.style.display = "flex";
                                return;
                            }
                            div.style.display = "none";
                            if (div.textContent.toLowerCase().includes(contactInput.value.toLowerCase())) {
                                div.style.display = "flex";
                            }
                        });
                    }
                });
                addContactButton.addEventListener('click', async () => {
                    const newContact = contactInput.value;
                    if (newContact === null || newContact.length === 0) {
                        console.log("Aborted");
                        throw new Error("No contact provided");
                    }
                    const publicKey = await this.callbacks.getUserPublicKey(newContact);
                    console.log("publicKey from server", publicKey);
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
                        this.contactDivs?.forEach(div => {div.style.display = "flex"});
                        addContactButton.click();
                    }
                });
                const closeContactInput = (event) => {
                    if (document.getElementById('contactControls').contains(event.target)) { return; }
                    if (document.getElementById('alertDiv')) { document.getElementById('alertDiv').remove(); }
                    this.contactDivs?.forEach(div => {div.style.display = "flex"});
                    contactInputDiv.remove();
                    document.removeEventListener('click', closeContactInput);
                }
                setTimeout(() => { document.addEventListener('click', closeContactInput) }, 5);
            }
        });

        this.backupButton.disabled = true;
        this.saveButton.disabled = true;

        this.saveButton.addEventListener('click', async (e) => {
            e.preventDefault();
            if (!this.currentGroupID) {
                this.showAlert("No conversation selected!");
                return;
            }
            const data = this.userInput.value;
            if (data.trim() === "") {
                this.showAlert("Message is empty");
                return;
            }
            const packageData = await this.callbacks.encryptMessage(this.currentGroupKey, data);
            console.log("packageData is", packageData);
            const messageJSON = JSON.stringify( {
                messageText: packageData,
                messageType: "message",
                username: this.username,
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

    async addConversation(messageData) {
        //console.log("messageDataID is", messageData.conversationID, "messageData.participants is", messageData.participants, "group key is", messageData.groupKey.slice(0, 4));
        const groupKey = await this.callbacks.decryptGroupKey(messageData.groupKey);
        this.conversationKeys.set(messageData.conversationID, groupKey);
        const newConversationDiv = document.createElement('div');
        newConversationDiv.classList = "conversationDiv";
        let chatDescription = "";
        messageData.participants.forEach(participant => {
            if (participant.username !== this.username) {
                chatDescription += participant.username + " ";
            }
        });
        if (messageData.participants.length === 1 && messageData.participants[0].username === this.username) {
            newConversationDiv.textContent = "My notes";
            this.lastActiveConversation = newConversationDiv;
        } else {
            newConversationDiv.textContent = chatDescription;
        }
        newConversationDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });
        newConversationDiv.addEventListener('click', async (event) => {
            if (this.currentGroupID === messageData.conversationID) {return;}
            this.lastActiveConversation.classList.remove("activeConversation");
            this.lastActiveConversation.classList.add("conversationDiv");
            this.lastActiveConversation = event.target;
            this.lastActiveConversation.classList = 'activeConversation';
            this.currentGroupID = messageData.conversationID;
            this.currentGroupKey = this.conversationKeys.get(messageData.conversationID);
            this.userMessages.innerHTML = "";
            const currentMessages = this.conversationMessages.get(messageData.conversationID) || [];
            for (const message of currentMessages) {
                await this.handleMessage(message);
            }
            this.userInput.focus();
            console.log("this.currentGroupID is", this.currentGroupID);
        });
        this.contactDiv.appendChild(newConversationDiv);
        return newConversationDiv;
    }
    
    createMessageElement = (message, id, timestamp, sender) => {
        let messageTimestamp;
        if (timestamp === undefined) {
            messageTimestamp = new Date();
        } else {
            messageTimestamp = timestamp;
        }
        const messageTime = new Date(Number(messageTimestamp));
        const formatted = `${String(messageTime.getHours()).padStart(2, 0)}:${String(messageTime.getMinutes()).padStart(2, 0)}`;
        const dayName = this.days[messageTime.getDay()];
        const messageContainer = document.createElement('div');
        const messageTextEl = document.createElement('div');
        const messageDayEl = document.createElement('div');
        const messageTimeEl = document.createElement('div');
        const messageDiv = document.createElement('div');
        if (sender === this.username) {
            messageContainer.classList = "clientMessageContainer";
        } else {
            messageContainer.classList = "contactMessageContainer";
        }
        messageDiv.classList = "messageDiv";
        messageTextEl.classList = "messageTextEl";
        messageDayEl.classList = "messageDayEl";
        messageTimeEl.classList = "messageTimeEl";
        messageTextEl.textContent = message;
        messageTextEl.id = id;
        messageDayEl.textContent = `${dayName}`;
        messageTimeEl.textContent = formatted;
        messageDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            if (messageDiv.parentElement.classList.contains("clientMessageContainer")) {
                this.createContextMenu(e.pageX, e.pageY, id, messageDiv, messageTimestamp);
            }
        });

        // IOS
        let pressTimer;
        const longPressDuration = 500;
        const startPress = (e) => {
            clearTimeout(pressTimer);
            pressTimer = setTimeout(() => {
                let x = e.touches ? e.touches[0].pageX : e.pageX;
                let y = e.touches ? e.touches[0].pageY : e.pageY;
                this.createContextMenu(x, y, id, messageDiv, messageTimestamp);
                // Haptic feedback on Android ( not for iOS yet)
                if (navigator.vibrate) navigator.vibrate(50);
            }, longPressDuration);
        };
        const cancelPress = () => {clearTimeout(pressTimer);};
        messageDiv.addEventListener('touchstart', startPress, { passive: true });
        messageDiv.addEventListener('touchend', cancelPress);
        //messageDiv.addEventListener('touchmove', cancelPress); 
        messageDiv.addEventListener('touchcancel', cancelPress);

        messageDiv.append(messageTextEl, messageDayEl, messageTimeEl);
        if (sender !== this.username) {
            const senderName = document.createElement('div');
            senderName.textContent = sender;
            senderName.classList = "senderName";
            messageContainer.append(senderName);
        }
        messageContainer.append(messageDiv);
        this.userMessages.appendChild(messageContainer);
        return messageDiv;
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
        contextMenu.style.top = `${y - 60}px`;
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
            const messageJSON = JSON.stringify({ id: messageId, username: this.callbacks.getUsername(), messageType: "delete", conversationID: this.currentGroupID });
            console.log(messageJSON);
            this.callbacks.wsSend(messageJSON);
            contextMenu.remove();
        });
        updateButton.addEventListener('click', () => {
            const inputElement = document.createElement('textarea');
            const sendButton = document.createElement('button');
            inputElement.id = "editMessageInput";
            inputElement.value = divToRemove.children[0].innerText;
            inputElement.style.height = divToRemove.children[0].offsetHeight + 'px';
            sendButton.id = "sendButton";
            sendButton.textContent = "Send";
            const unUpdatedMessage = divToRemove.children[0]
            divToRemove.children[0].replaceWith(inputElement);
            inputElement.after(sendButton);
            inputElement.focus();

            inputElement.addEventListener('input', () => {                
                inputElement.style.height = inputElement.scrollHeight + 'px'
            });

            sendButton.addEventListener('click', async () => {
                const updatedDiv = document.createElement("div");
                updatedDiv.classList = "messageTextEl";
                let newMessage;
                try {
                    newMessage = await this.callbacks.encryptMessage(this.currentGroupKey, inputElement.value, messageTimestamp);
                } catch (e) {
                    console.log("Error", e);
                }
                updatedDiv.textContent = inputElement.value;
                updatedDiv.id = messageId;
                inputElement.replaceWith(updatedDiv);
                const messageJSON = JSON.stringify({ id: messageId, "messageText": newMessage, username: this.callbacks.getUsername(), messageType: "update", conversationID: this.currentGroupID });
                console.log(messageJSON);
                this.callbacks.wsSend(messageJSON);
                sendButton.remove()
            });

            inputElement.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    inputElement.replaceWith(unUpdatedMessage);
                }
                if (e.key === 'Enter') {
                    sendButton.click();
                }
            });
            
            setTimeout(() => {
                document.addEventListener('click', (event) => {
                    if (divToRemove.contains(event.target)) {
                        return;
                    } else {
                        inputElement.replaceWith(unUpdatedMessage);
                        sendButton.remove()
                    }
                });
            }, 5);
            contextMenu.remove();
        });
        const closeMenu = (e) => {
            if (!contextMenu.contains(e.target)) {
                contextMenu.remove();
                document.removeEventListener('click', closeMenu);
            }
        }
        setTimeout(() => {
            document.addEventListener('click', closeMenu);
        }, 5);
        document.body.append(contextMenu);
    }

    setFormVisibility(event) {
        if (event.type === "open") {
            this.connectionTitle.style.display = "none";
            const mobileToggle = document.querySelectorAll(".mobile-toggle");
            mobileToggle.forEach((item) => {
                item.classList.add("isHidden");
            });
            document.getElementById("chatDiv").style.display = "none";
            const localUsername = this.callbacks.getUsername();
            if (localUsername !== null) {
                this.logInForm.style.display = "flex";
                this.loginUsernameInput.value = localUsername;
            } else {
                this.registrationForm.style.display = "flex";
                this.registerUsernameInput.focus();
            }
        } else if (event.type === "close") {
            const mobileToggle = document.querySelectorAll(".mobile-toggle");
            mobileToggle.forEach((item) => {
                item.classList.add("isHidden");
            });
            this.connectionTitle.style.display = "flex";
        }
    }

    clearInputs() {
          this.loginPasswordInput.value = "";
          this.registerUsernameInput.value = "";
          this.registerPasswordInput.value = "";
          this.registerPasswordInputConfirm.value = "";
    }

    handleUsernameAvailability(messageData) {
        if (!messageData.available) {
            this.usernameAvailable = false;
            this.registerUsernameInputLabel.textContent = `Username ${messageData.username + " " + messageData.messageText}`;
            this.registerUsernameInputLabel.style.color = 'pink';
        } else {
            this.usernameAvailable = true;
            this.registerUsernameInputLabel.textContent = `Username ${messageData.username + " " + messageData.messageText}`;
            this.registerUsernameInputLabel.style.color = 'lightgreen';
        }
        console.log(messageData);
    }

    async handleInitialCase(messageData) {
        this.username = this.callbacks.getUsername();
        this.registerUsernameInput.value = "";
        this.registrationForm.style.display = "none";
        this.logInForm.style.display = "none";
        const mobileToggle = document.querySelectorAll(".mobile-toggle");
            mobileToggle.forEach((item) => {
                item.classList.remove("isHidden");
            });
        
        if (messageData.userRole === "admin") {            
            const secureHTML = (text) => {
                return String(text)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
            }
            this.#role = "admin";
            console.log(this.#role, "is yor role");            
            const adminDiv = document.getElementById("adminDiv");
            const adminbutton = document.getElementById("adminButton");
            const adminTable = document.getElementById("adminTable");
            const adminTableBody = document.getElementById("adminTableBody");
            adminDiv.style.display = "flex";
            adminbutton.style.display = "block";
            adminTable.style.display = "block";
            adminTableBody.style.display = "block";
            this.contactContainer.style.display = "none";
            this.chatDiv.style.display = "none";
            this.backupControls.style.display = "flex";
            adminTableBody.innerHTML = "";
            let row;
            messageData.users.forEach(user => {
                //const timestamp = new Date(message.messageTime);
                //const formattedTimestamp = `${String(timestamp.getDate())} ${String(this.months[timestamp.getMonth()])} ${String(timestamp.getHours()).padStart(2, 0)}:${String(timestamp.getMinutes()).padStart(2, 0)}`
                row =  `<tr><th>${secureHTML(user.username)}</th><td>${secureHTML(user.userRole)}</td><td>${"formattedTimestamp"}</td></tr>`
                adminTableBody.innerHTML += row;
            });
            adminbutton.addEventListener('click', () => {
                if (adminbutton.textContent === "Show database") {
                    adminbutton.textContent = "Show chats";
                    this.contactContainer.style.display = "none";
                    this.chatDiv.style.display = "none";
                    adminDiv.style.display = "flex";
                    adminTable.style.display = "block";
                } else {
                    adminDiv.style.display = "none";
                    //adminTableBody.innerHTML = ""; // will need to change to textContent
                    adminbutton.textContent = "Show database";
                    adminTable.style.display = "none";
                    this.chatDiv.style.display = "flex";
                    this.contactContainer.style.display = "flex";
                }
                if (this.#role === "admin") {
                    adminTableBody.innerHTML = "";
                    let row;
                    messageData.users.forEach(user => {
                        //const timestamp = new Date(message.messageTime);
                        //const formattedTimestamp = `${String(timestamp.getDate())} ${String(this.months[timestamp.getMonth()])} ${String(timestamp.getHours()).padStart(2, 0)}:${String(timestamp.getMinutes()).padStart(2, 0)}`
                        row =  `<tr><th>${secureHTML(user.username)}</th><td>${secureHTML(user.userRole)}</td><td>${"formattedTimestamp"}</td></tr>`
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
            this.chatDiv.style.display = "flex";
            this.backupControls.style.display = "flex";
            this.contactContainer.style.display = "flex";
        }
        this.userMessages.innerHTML = "";
        this.contactDiv.innerHTML = "";
        for (const conversation of messageData.conversations) {
            const messageArray = [];
            conversation.messages.forEach(message => {
                const formattedMessage = {
                    id: message.id,
                    messageText: message.messageText,
                    messageTime: message.messageTime,
                    sender: message.senderUsername
                }
                messageArray.push(formattedMessage);
            });
            this.conversationMessages.set(conversation.conversationID, messageArray);
            await this.addConversation(conversation);
        }
        this.backupButton.disabled = false;
        this.saveButton.disabled = false;
        this.scrollToBottom();
    }

    async handleMessage(messageData) {
        const decryptedMessage = await this.callbacks.decryptMessage(this.currentGroupKey, messageData.messageText);
        this.createMessageElement(decryptedMessage.message, messageData.id, decryptedMessage.receivedTimestamp, messageData.sender);
        this.scrollToBottom();
    }

    async addMessageToConversation(messageData) {
        const currentMessages = this.conversationMessages.get(messageData.conversationID);
        const formattedMessage = {
            id: messageData.id,
            messageText: messageData.messageText,
            messageTime: messageData.messageTime,
            sender: messageData.sender
        }
        currentMessages.push(formattedMessage);
        this.conversationMessages.set(messageData.conversationID, currentMessages);
        if (this.currentGroupID === messageData.conversationID) {
            await this.handleMessage(messageData);
        }
    }

    async updateMessage(messageData) {
        const messages = this.conversationMessages.get(messageData.conversationID);
        if (messages) {
            const message = messages.find(m => m.id === messageData.id);
            if (message) {
                message.messageText = messageData.messageText;
            }
        }
        if (this.currentGroupID === messageData.conversationID) {
            const divToUpdate = document.getElementById(messageData.id);
            const decryptedMessage = await this.callbacks.decryptMessage(this.currentGroupKey, messageData.messageText);
            divToUpdate.textContent = decryptedMessage.message;
        }
    }

    removeMessage(messageData) {
        if (this.currentGroupID === messageData.conversationID) {
            const divToRemove = document.getElementById(messageData.id).parentElement.parentElement;
            divToRemove.remove();
        }
        const messages = this.conversationMessages.get((messageData.conversationID));
        if (messages) {
            this.conversationMessages.set(
                messageData.conversationID,
                messages.filter(m => m.id !== messageData.id)
            );
        }
    }

    async confirmGroupChat(messageData) {
        console.log("messageDataID is", messageData.conversationID, "messageData.participants is", messageData.participants, "group key is", messageData.groupKey.slice(0, 4));
        this.conversationMessages.set(messageData.conversationID, []);
        const groupKey = await this.callbacks.decryptGroupKey(messageData.groupKey);
        this.conversationKeys.set(messageData.conversationID, groupKey);
        const newConversationDiv = document.createElement('div');
        newConversationDiv.classList = "conversationDiv";
        let chatDescription = "";
        messageData.participants.forEach(participant => {
            if (participant.username !== this.username) {
                chatDescription += participant.username + " ";
            }
        });
        newConversationDiv.textContent = chatDescription;
        newConversationDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
        });

        newConversationDiv.addEventListener('click', async (event) => {
            this.lastActiveConversation.classList.remove('activeConversation');
            this.lastActiveConversation.classList.add('conversationDiv');
            this.lastActiveConversation = event.target;
            this.lastActiveConversation.classList = 'activeConversation';
            this.currentGroupID = messageData.conversationID;
            this.currentGroupKey = this.conversationKeys.get(messageData.conversationID);
            this.userMessages.innerHTML = "";
            const currentMessages = this.conversationMessages.get(messageData.conversationID) || [];
            for (const message of currentMessages) {
                await this.handleMessage(message);
            }
            console.log("this.conversationMessages is", this.conversationMessages);
            this.userInput.focus();
            console.log("this.currentGroupID is", this.currentGroupID, "this.currentGroupKey is", this.currentGroupKey);
        });
        this.contactDiv.appendChild(newConversationDiv);
        this.contactDivs = document.querySelectorAll(".conversationDiv");
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