const crypto = require('crypto');
const { RSA_NO_PADDING } = require('constants');

function encryptPinBlock(PIN, CardNumber, PublicKey, plainText) {
    let hexPINBlock = ("0" + PIN.length + PIN).padEnd(16, 'F');
    CardNumber = CardNumber.substring(0, CardNumber.length - 1);
    let hexCardlock = ("0000" + CardNumber.substring(CardNumber.length - 12));
    
    let dec1 = BigInt('0x' + hexPINBlock);
    let dec2 = BigInt('0x' + hexCardlock);
    let result = dec1 ^ dec2;
    let hexResult = result.toString(16).toUpperCase();

    if (hexResult.length < 16) {
        hexResult = "0" + hexResult;
    }

    let hexStringResult = Buffer.from(hexResult, 'hex').toString('hex');

    // RSA Encryption
    const publicKeyBuffer = Buffer.from(PublicKey, 'base64');
    const rsaKey = crypto.createPublicKey({
        key: publicKeyBuffer,
        format: 'der',
        type: 'spki'
    });

    const encryptedBuffer = crypto.publicEncrypt(
        {
            key: rsaKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        },
        Buffer.from(plainText)
    );

    const encryptedText = encryptedBuffer.toString('base64');
    return encryptedText;
}

// Example usage:
const PIN = '5678';
const CardNumber = '5213636125746050';
const PublicKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8MFxB0tQiBpIXLwMYQOF35JqN4gDqKjLPvlwtBzj+iyo/ogXDkVex1ls8xEe4/gC68Lf/LpkUVORo31yOvW3MYkGEZ/xzwF8+5fxQsNJb/bA0xpNtikN0FaEYqz/FTpn2r0vgB4Km3K5fbcMfjDyIw1YUWQZc0ShSPjO959lEUvRddoIXyzrRGbp8aigwye7dHwumFzeXcmGNX6TY3TZ6qU0p7ol6pS4XSeNIsW93tT62WvNAcOOgs99WXQMEVlZ9IYnig9c6qUOLyHcG6JJF0PyeH2FWLqBoT17b575uBrUC93FQ9Nba5trJBinZSQXzV6RoyHuLU/z9ZIGdySxQIDAQAB';
const plainText = 'SomeTextToEncrypt';

const encryptedText = encryptPinBlock(PIN, CardNumber, PublicKey, plainText);
console.log(encryptedText);
