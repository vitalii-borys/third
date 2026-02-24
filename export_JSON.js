const messages = [
  { id: 1, text: "Hello" },
  { id: 2, text: "World" }
];
console.log(messages);
const myString = JSON.stringify(messages);
const myBlob = new Blob([myString], { type: "application/json" });
const myUrl = URL.createObjectURL(myBlob);

const myLink = document.createElement('a');
myLink.textContent = "Download Backup";
myLink.target = "_blank";
myLink.rel = "noopener noreferrer";
myLink.href = myUrl;
myLink.download = "Backup.json";
document.body.appendChild(myLink);

const fileUpload = document.createElement('input');
const submitButton = document.createElement('button');
submitButton.textContent = "Submit";
fileUpload.type = 'file';
fileUpload.accept = 'application/json';
document.body.appendChild(fileUpload);
document.body.appendChild(submitButton);
submitButton.addEventListener("click", () => {
  const file = fileUpload.files[0];
  let myImportedJSON;
  const reader = new FileReader();
  reader.onload = function() {
    myImportedJSON = JSON.parse(reader.result);
    console.log(myImportedJSON);
  };
  reader.readAsText(file);
});
fileUpload.addEventListener("change", (event) => {
  const file = fileUpload.files[0];
  console.log(file.name);
})
