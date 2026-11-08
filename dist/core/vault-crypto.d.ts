export declare function isEncryptedVault(content: string): boolean;
/** Encrypts the JSON produced by `vault.toJSON()` */
export declare function encryptVaultJson(json: string, passphrase: string): string;
/** Decrypts an encrypted vault file back to the JSON accepted by `Vault.fromJSON` */
export declare function decryptVaultJson(content: string, passphrase: string): string;
