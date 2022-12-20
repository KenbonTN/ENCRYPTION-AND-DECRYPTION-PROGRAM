function encryptMessage() {
    var message = document.getElementById('encryption').value;
    var password = document.getElementById('encryption-key').value;
    var encryptedMessage = CryptoJS.AES.encrypt(message, password).toString();
    document.getElementById('encrypted-result').value = encryptedMessage;
}
function decryptMessage() {
    var message = document.getElementById('decryption').value;
    var password = document.getElementById('password').value;
    var decryptedMessage = CryptoJS.AES.decrypt(message, password).toString(CryptoJS.enc.Utf8);
    document.getElementById('decrypted-result').value = decryptedMessage;
}  