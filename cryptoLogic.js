// This file contains the exact same encryption/decryption functions
// from our original CLI tool, just exported for use in our server.

const crypto = require('crypto');

// --- CONFIGURATION ---
const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32; // 32 bytes = 256 bits (for AES-256)
const SALT_BYTES = 16;
const IV_BYTES = 16; // Initialization Vector
const AUTH_TAG_BYTES = 16;
const SCRYPT_OPTIONS = {
  N: 16384, // CPU/memory cost factor (power of 2)
  r: 8,     // Block size
  p: 1,     // Parallelization factor
};
const ENCODING = 'hex'; // 'hex' or 'base64'
const SEPARATOR = ':';   // Separator for the output string

/**
 * Derives a strong encryption key from a password using scrypt.
 * @param {string} password - The user's password.
 * @param {Buffer} salt - A random salt.
 * @returns {Promise<Buffer>} A 32-byte (256-bit) encryption key.
 */
function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_BYTES, SCRYPT_OPTIONS, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey);
    });
  });
}

/**
 * Encrypts a piece of text (plaintext).
 * @param {string} text - The plaintext to encrypt.
 * @param {string} password - The password to use for encryption.
 * @returns {Promise<string>} A combined string: salt:iv:authTag:ciphertext
 */
async function encrypt(text, password) {
  try {
    const salt = crypto.randomBytes(SALT_BYTES);
    const key = await deriveKey(password, salt);
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_BYTES
    });

    let encrypted = cipher.update(text, 'utf8', ENCODING);
    encrypted += cipher.final(ENCODING);
    const authTag = cipher.getAuthTag();

    return [
      salt.toString(ENCODING),
      iv.toString(ENCODING),
      authTag.toString(ENCODING),
      encrypted
    ].join(SEPARATOR);

  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * Decrypts a combined string back into text.
 * @param {string} combinedStr - The "salt:iv:authTag:ciphertext" string.
 * @param {string} password - The password used for encryption.
 *@returns {Promise<string>} The original decrypted text.
 */
async function decrypt(combinedStr, password) {
  try {
    const parts = combinedStr.split(SEPARATOR);
    if (parts.length !== 4) {
      throw new Error('Invalid encrypted data format.');
    }

    const [saltHex, ivHex, authTagHex, encryptedHex] = parts;
    const salt = Buffer.from(saltHex, ENCODING);
    const iv = Buffer.from(ivHex, ENCODING);
    const authTag = Buffer.from(authTagHex, ENCODING);
    const encrypted = Buffer.from(encryptedHex, ENCODING);

    const key = await deriveKey(password, salt);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_BYTES
    });

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, ENCODING, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;

  } catch (error) {
    // This error is *expected* if the password is wrong
    console.error('Decryption failed. Check password or data integrity.');
    throw new Error('Decryption failed');
  }
}

// Export the functions to be used in server.js
module.exports = { encrypt, decrypt };
