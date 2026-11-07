import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

/**
 * Passphrase-encrypted vault files (AES-256-GCM, key derived with scrypt).
 * The header (format, version, KDF parameters, salt) is bound to the ciphertext as
 * additional authenticated data, so weakening the KDF parameters or swapping the salt
 * makes decryption fail instead of silently using cheaper parameters.
 */
const FORMAT = 'agent-redact-vault';
const VERSION = 1;
const KDF = { name: 'scrypt', N: 32768, r: 8, p: 1 } as const;

interface EncryptedVaultFile {
  format: typeof FORMAT;
  version: typeof VERSION;
  kdf: { name: 'scrypt'; N: number; r: number; p: number; salt: string };
  cipher: 'aes-256-gcm';
  iv: string;
  tag: string;
  data: string;
}

function headerAad(file: Pick<EncryptedVaultFile, 'format' | 'version' | 'kdf' | 'cipher'>): Buffer {
  return Buffer.from(JSON.stringify([file.format, file.version, file.kdf, file.cipher]), 'utf8');
}

/** Fixed memory ceiling for the format's scrypt parameters (128·N·r = 32 MiB, plus headroom) */
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

/**
 * Cost parameters are part of the format version, never taken from the file: a hostile
 * vault with N=2^30 would otherwise make scrypt allocate gigabytes (denial of service).
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase.normalize('NFC'), salt, 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: SCRYPT_MAXMEM });
}

function hasExpectedKdf(kdf: unknown): kdf is { name: 'scrypt'; N: number; r: number; p: number; salt: string } {
  const k = kdf as Record<string, unknown> | null;
  return (
    !!k &&
    k['name'] === KDF.name &&
    k['N'] === KDF.N &&
    k['r'] === KDF.r &&
    k['p'] === KDF.p &&
    typeof k['salt'] === 'string' &&
    Buffer.from(k['salt'], 'base64').length === 16
  );
}

export function isEncryptedVault(content: string): boolean {
  try {
    const parsed = JSON.parse(content) as Partial<EncryptedVaultFile>;
    return parsed?.format === FORMAT;
  } catch {
    return false;
  }
}

/** Encrypts the JSON produced by `vault.toJSON()` */
export function encryptVaultJson(json: string, passphrase: string): string {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('A non-empty passphrase is required to encrypt a vault');
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const kdf = { ...KDF, salt: salt.toString('base64') };
  const header = { format: FORMAT, version: VERSION, kdf, cipher: 'aes-256-gcm' } as const;
  const cipher = createCipheriv('aes-256-gcm', deriveKey(passphrase, salt), iv);
  cipher.setAAD(headerAad(header));
  const data = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const file: EncryptedVaultFile = {
    ...header,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64')
  };
  return JSON.stringify(file, null, 2) + '\n';
}

/** Decrypts an encrypted vault file back to the JSON accepted by `Vault.fromJSON` */
export function decryptVaultJson(content: string, passphrase: string): string {
  const fail = () => new Error('Cannot decrypt vault: wrong passphrase or corrupted file');
  let file: EncryptedVaultFile;
  try {
    file = JSON.parse(content) as EncryptedVaultFile;
  } catch {
    throw fail();
  }
  if (file?.format !== FORMAT || file.version !== VERSION || file.cipher !== 'aes-256-gcm' || !hasExpectedKdf(file.kdf)) {
    throw fail();
  }
  try {
    const key = deriveKey(passphrase, Buffer.from(file.kdf.salt, 'base64'));
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'base64'));
    decipher.setAAD(headerAad(file));
    decipher.setAuthTag(Buffer.from(file.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(file.data, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw fail();
  }
}
