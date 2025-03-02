import { webcrypto } from "crypto";
import * as console from "console";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // Generate RSA key pair using the crypto module
  const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: {name: "SHA-256"},
      },
      true,
      ["encrypt", "decrypt"]
  );
  return { publicKey, privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export public key to PEM format
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exportedKey);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
    key: webcrypto.CryptoKey | null
): Promise<string | null> {

  if (!key) return null; // Return null if the key is null

  // Export the private key to PKCS8 format
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);

  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string public key to its native format
export async function importPubKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  // Decode the base64 string to ArrayBuffer
  const keyBuffer = base64ToArrayBuffer(strKey);

  // Import the public key from the ArrayBuffer
  const importedKey = await webcrypto.subtle.importKey(
      "spki",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" },
      },
      true,
      ["encrypt"]
  );

  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  // Decode the base64 string to ArrayBuffer
  const arrayBuffer = base64ToArrayBuffer(strKey);

  // Import the private key from the ArrayBuffer
  const importedKey = await webcrypto.subtle.importKey(
      "pkcs8",
      arrayBuffer,
      {
        name: "RSA-OAEP",
        hash: { name: "SHA-256" },
      },
      true,
      ["decrypt"]
  );

  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
  // Decode the base64 encoded message to ArrayBuffer
  const dataBuffer = base64ToArrayBuffer(b64Data);

  // Import the public key
  const publicKey = await importPubKey(strPublicKey);

  // Encrypt the data using the public key
  const encryptedBuffer = await webcrypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publicKey,
      dataBuffer
  );

  return arrayBufferToBase64(encryptedBuffer);;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
  // Decode the base64 encoded message to ArrayBuffer
  const encryptedBuffer = base64ToArrayBuffer(data);

  // Decrypt the data using the private key
  const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      encryptedBuffer
  );
  return arrayBufferToBase64(decryptedBuffer);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // Generate a random symmetric key
  const key = await webcrypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256, // Key size
      },
      true, // Exportable
      ["encrypt", "decrypt"] // Key usages
  );

  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the symmetric key
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);

  // Convert the exported key to base64 string
  const base64Key = arrayBufferToBase64(exportedKey);

  return base64Key;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
    strKey: string
): Promise<webcrypto.CryptoKey> {
  // Convert the base64 string to ArrayBuffer
  const arrayBufferKey = base64ToArrayBuffer(strKey);

  // Import the symmetric key
  const importedKey = await webcrypto.subtle.importKey(
      "raw",
      arrayBufferKey,
      { name: "AES-CBC" },
      true,
      ["encrypt", "decrypt"]
  );

  return importedKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
  // Encode the data to a Uint8Array
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(16));

  // Encrypt the data using the symmetric key
  const encryptedBuffer = await webcrypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      encodedData
  );

  const concatenatedData = new Uint8Array([...iv, ...new Uint8Array(encryptedBuffer)]);

  return arrayBufferToBase64(concatenatedData.buffer);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
    strKey: string,
    encryptedData: string
): Promise<string> {
  // Decode the base64 encoded message to ArrayBuffer
  const encryptedBuffer = base64ToArrayBuffer(encryptedData);

  // Convert the base64 string key to a CryptoKey
  const key = await importSymKey(strKey);

  const iv = encryptedBuffer.slice(0, 16);

  // Decrypt the data using the symmetric key
  const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      encryptedBuffer.slice(16)
  );

  return new TextDecoder().decode(decryptedBuffer);
}