const CURRENT_VERSION = "1";

function readWTelegramSessionFile(filename, apiHash) {
    const apiHashBytes = Uint8Array.from(
        Array.from({length: apiHash.length / 2}, (_, i) => 
            parseInt(apiHash.substring(i * 2, i * 2 + 2), 16)
        )
    );
    const fs = require('fs');
    const crypto = require('crypto');

    let store;
    try {
        store = fs.openSync(filename, 'r');
        const stats = fs.fstatSync(store);
        const totalLength = stats.size;
        
        if (totalLength === 0) {
            fs.closeSync(store);
            return "";
        }

        const header = Buffer.alloc(8);
        const headerBytesRead = fs.readSync(store, header, 0, 8, 0);
        if (headerBytesRead !== 8) {
            throw new Error(`Can't read session header`);
        }

        const position = header.readUInt32LE(0);
        const dataLength = header.readUInt32LE(4);

        if (position + dataLength > totalLength) {
            throw new Error(`Invalid session file: position (${position}) + length (${dataLength}) exceeds file size (${totalLength})`);
        }

        const encrypted = Buffer.alloc(dataLength);
        const bytesRead = fs.readSync(store, encrypted, 0, dataLength, position);
        if (bytesRead !== dataLength) {
            throw new Error(`Can't read session block (${position}, ${dataLength})`);
        }

        const iv = encrypted.subarray(0, 16);
        const encryptedPayload = encrypted.subarray(16);

        const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(apiHashBytes), iv);
        const decrypted = Buffer.concat([
            decipher.update(encryptedPayload),
            decipher.final()
        ]);

        const sha256 = crypto.createHash('sha256');
        sha256.update(decrypted.subarray(32));
        const hash = sha256.digest();
        const storedHash = decrypted.subarray(0, 32);

        if (!storedHash.equals(hash)) {
            throw new Error("Integrity check failed in session loading");
        }

        fs.closeSync(store);
        return decrypted.subarray(32).toString('utf8');
    } catch (ex) {
        if (store !== undefined) fs.closeSync(store);
        throw new Error(`Exception while reading session file: ${ex.message}\nUse the correct api_hash/id/key, or delete the file to start a new session`);
    }
}

function toSessionStr(authkey, setveraddr, port, dcId) {
    const _key = authkey;

    const dcBuffer = Buffer.from([dcId]);
    const addressBuffer = Buffer.from(setveraddr);
    const addressLengthBuffer = Buffer.alloc(2);
    addressLengthBuffer.writeInt16BE(addressBuffer.length, 0);
    const portBuffer = Buffer.alloc(2);
    portBuffer.writeInt16BE(port, 0);

    return (
        CURRENT_VERSION +
        encode(
            Buffer.concat([
                dcBuffer,
                addressLengthBuffer,
                addressBuffer,
                portBuffer,
                _key,
            ])
        )
    );
}


function encode(x) {
    return x.toString("base64");
}

const args = process.argv.slice(2);
if (args.length < 2) {
    console.log("WTelegram session file to GramJS session string converter");
    console.log("--------------------------------");
    console.log("This tool converts a WTelegram session file to a GramJS session string.");
    console.log("--------------------------------");
    console.log("Usage: node toSessionStr.js <sessionFile> <apiHash>");
    console.log("Example: node toSessionStr.js wtelegram.session XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    process.exit(1);
}

const sessionFile = args[0];
const apiHash = args[1];

try {
    const sessionStr = readWTelegramSessionFile(sessionFile, apiHash);
    const sessionData = JSON.parse(sessionStr);
    const mainDc = sessionData.MainDC;
    const dcSession = sessionData.DCSessions[mainDc];

    if (!dcSession) {
        console.error("DC session not found for MainDC:", mainDc);
        process.exit(1);
    }

    const authKeyBase64 = dcSession.AuthKey;
    const authKeyBytes = Buffer.from(authKeyBase64, 'base64');
    const serverAddress = dcSession.DataCenter.ip_address;
    const port = dcSession.DataCenter.port;
    const dcId = dcSession.DataCenter.id;

    const sessionString = toSessionStr(authKeyBytes, serverAddress, port, dcId);

    console.log("GramJS Session String:");
    console.log(sessionString);
} catch (error) {
    console.error("Error:", error.message);
    process.exit(1);
}
