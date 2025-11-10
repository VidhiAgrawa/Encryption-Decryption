const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 16;
const AUTH_TAG_BYTES = 16;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1 };
const ENCODING = 'hex';
const SEPARATOR = ':';

function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_BYTES, SCRYPT_OPTIONS, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey);
    });
  });
}

async function encrypt(text, password) {
  try {
    const salt = crypto.randomBytes(SALT_BYTES);
    const key = await deriveKey(password, salt);
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });

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
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, ENCODING, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;

  } catch (error) {
    console.error('Decryption failed. Check password or data integrity.');
    throw new Error('Decryption failed');
  }
}

module.exports = { encrypt, decrypt };
