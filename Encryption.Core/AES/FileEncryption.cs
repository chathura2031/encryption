using System.Security.Cryptography;

namespace Encryption.Core.AES;

public static class FileEncryption
{
    /// <summary>
    /// Get a new AES instance
    /// </summary>
    /// <param name="key">The key to use</param>
    /// <param name="iv">The IV to use (optional)</param>
    /// <returns>A reference to an AES instance</returns>
    private static Aes GetAesInstance(string key, string? iv = null)
    {
        Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = Convert.FromBase64String(key);
        
        if (iv != null) { aes.IV = Convert.FromBase64String(iv); }
        else { aes.GenerateIV(); }
        
        aes.Padding = PaddingMode.PKCS7;
        aes.Mode = CipherMode.ECB;

        return aes;
    }

    /// <summary>
    /// Load a key file at a specified location or generate a key, save it to that location
    /// and load the file
    /// </summary>
    /// <param name="keyPath">The path to the file where the key is located</param>
    /// <returns>The key contained in the key file</returns>
    public static string LoadOrGenerateKey(string keyPath)
    {
        using Aes aes = Aes.Create();

        if (!File.Exists(keyPath))
        {
            string key = GenerateKey();
            File.WriteAllText(keyPath, key);
            return key;
        }
        
        return File.ReadAllText(keyPath);
    }

    /// <summary>
    /// Generate a new key
    /// </summary>
    /// <returns>The newly generated key</returns>
    public static string GenerateKey()
    {
        using Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        return Convert.ToBase64String(aes.Key);
    }

    /// <summary>
    /// Decrypt all files then encrypt all files using a new key
    /// </summary>
    /// <param name="folderPath">The directory to encrypt the files in</param>
    /// <param name="exceptions">A set of folders and files to ignore</param>
    /// <param name="key">The key to use for decryption</param>
    /// <returns>The new key used for encryption</returns>
    public static string RotateKey(string folderPath, HashSet<string> exceptions, string key)
    {
        DecryptAll(folderPath, exceptions, key, true);
        
        string newKey = GenerateKey();
        EncryptAll(folderPath, exceptions, newKey, true);
        
        return newKey;
    }
    
    /// <summary>
    /// Encrypt a file
    /// </summary>
    /// <param name="filePath">The path to the file to encrypt</param>
    /// <param name="cypherFilePath">The path to the encrypted file</param>
    /// <param name="aes">A reference to an AES instance</param>
    /// <param name="deleteOriginal">True if the original file should be deleted, False otherwise</param>
    /// <returns>The IV used for encryption</returns>
    private static string Encrypt(string filePath, string cypherFilePath, Aes aes, bool deleteOriginal = false)
    {
        using FileStream fp = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using FileStream encryptedFile = new FileStream(cypherFilePath, FileMode.Create);

        aes.GenerateIV();
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        CryptoStream cryptoStream = new CryptoStream(encryptedFile, encryptor, CryptoStreamMode.Write);
        
        byte[] buffer = new byte[1024];
        int read;

        while((read = fp.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, read);
        }
        cryptoStream.FlushFinalBlock();

        if (deleteOriginal)
        {
            File.Delete(filePath);
        }

        return Convert.ToBase64String(aes.IV);
    }

    /// <summary>
    /// Encrypt a file
    /// </summary>
    /// <param name="filePath">The path to the file to encrypt</param>
    /// <param name="cypherFilePath">The path to the encrypted file</param>
    /// <param name="key">The key to use for encryption</param>
    /// <param name="deleteOriginal">True if the original file should be deleted, False otherwise</param>
    /// <returns>The IV used for encryption</returns>
    public static string Encrypt(string filePath, string cypherFilePath, string key, bool deleteOriginal = false)
    {
        using Aes aes = GetAesInstance(key);
        return Encrypt(filePath, cypherFilePath, aes, deleteOriginal);
    }

    /// <summary>
    /// Encrypt multiple files
    /// </summary>
    /// <param name="filePaths">The paths to the files to encrypt</param>
    /// <param name="cypherFilePaths">The paths to the encrypted files</param>
    /// <param name="key">The key to use for encryption</param>
    /// <param name="deleteOriginal">True if the original file should be deleted, False otherwise</param>
    /// <returns>The IVs used for encryption</returns>
    /// <exception cref="ArgumentException">Thrown if the number of file paths and cypher file paths are different</exception>
    public static string[] Encrypt(string[] filePaths, string[] cypherFilePaths, string key, bool deleteOriginal = false)
    {
        if (filePaths.Length != cypherFilePaths.Length)
        {
            throw new ArgumentException("filePath and encryptedFilePath count mismatch. They must both be of the same length.");
        }

        string[] ivs = new string[filePaths.Length];
        using Aes aes = GetAesInstance(key);
        
        for (int i = 0; i < filePaths.Length; i++)
        {
            ivs[i] = Encrypt(filePaths[i], cypherFilePaths[i], aes, deleteOriginal);
        }
        
        return ivs;
    }

    /// <summary>
    /// Encrypt all files in a given directory
    /// </summary>
    /// <param name="folderPath">The directory to encrypt the files in</param>
    /// <param name="exceptions">A set of folders and files to ignore</param>
    /// <param name="key">The key to use for encryption</param>
    /// <param name="deleteOriginal">True if the original file should be deleted, False otherwise</param>
    /// <exception cref="ArgumentException">Thrown if the number of ivs and files to encrypt are different</exception>
    public static void EncryptAll(string folderPath, HashSet<string> exceptions, string key, bool deleteOriginal = false)
    {
        Queue<string> paths = new Queue<string>();
        paths.Enqueue(folderPath);

        LinkedList<string> toEncrypt = [];
        LinkedList<string> encrypted = [];
        while (paths.Count > 0)
        {
            string path = paths.Dequeue();
            // Ignore excepted folders
            if (path.Length > folderPath.Length && exceptions.Contains(path.Substring(folderPath.Length + 1)))
            {
                continue;
            }

            // Add all sub-folders to be processed
            foreach (string dir in Directory.GetDirectories(path))
            {
                paths.Enqueue(dir);
            }

            // Add to the list of files to encrypt
            foreach (string file in Directory.EnumerateFiles(path))
            {
                // Ignore excepted and already encrypted files
                if (file.Substring(file.Length - 4) == ".gpg" || file.Substring(file.Length - 3) == ".iv" ||
                    exceptions.Contains(file.Substring(folderPath.Length + 1)))
                {
                    continue;
                }

                toEncrypt.AddLast(file);
                encrypted.AddLast(file + ".gpg");
            }
        }

        string[] ivs = Encrypt(toEncrypt.ToArray(), encrypted.ToArray(), key, deleteOriginal);
        if (ivs.Length != toEncrypt.Count)
        {
            throw new ArgumentException("ivs and toEncrypt count mismatch. They must both be of the same length.");
        }

        int i = 0;
        foreach (string file in toEncrypt)
        {
            File.WriteAllText(file + ".iv", ivs[i]);
            i++;
        }
    }
    
    /// <summary>
    /// Decrypt a file
    /// </summary>
    /// <param name="cypherFilePath">The path to the file to decrypt</param>
    /// <param name="decryptedFilePath">The path to the decrypted file</param>
    /// <param name="key">The key to use for decryption</param>
    /// <param name="iv">The IV to use for decryption</param>
    /// <param name="aes">A reference to an AES instance</param>
    /// <param name="deleteCypher">True if the cypher file should be deleted, False otherwise</param>
    private static void Decrypt(string cypherFilePath, string decryptedFilePath, string key, string iv, Aes aes, bool deleteCypher = false)
    {
        using FileStream fp = new FileStream(cypherFilePath, FileMode.Open, FileAccess.Read);
        using FileStream decryptedFile = new FileStream(decryptedFilePath, FileMode.Create);

        aes.Padding = PaddingMode.PKCS7;
        ICryptoTransform decryptor = aes.CreateDecryptor(Convert.FromBase64String(key), Convert.FromBase64String(iv));
        CryptoStream cryptoStream = new CryptoStream(fp, decryptor, CryptoStreamMode.Read);

        byte[] buffer = new byte[1024];
        int read;
        while((read = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            decryptedFile.Write(buffer, 0, read);
        }
        decryptedFile.Flush();

        if (deleteCypher)
        {
            File.Delete(cypherFilePath);
        }
    }

    /// <summary>
    /// Decrypt a file
    /// </summary>
    /// <param name="cypherFilePath">The path to the file to decrypt</param>
    /// <param name="decryptedFilePath">The path to the decrypted file</param>
    /// <param name="key">The key to use for decryption</param>
    /// <param name="iv">The IV to use for decryption</param>
    /// <param name="deleteCypher">True if the cypher file should be deleted, False otherwise</param>
    public static void Decrypt(string cypherFilePath, string decryptedFilePath, string key, string iv, bool deleteCypher = false)
    {
        using Aes aes = GetAesInstance(key, iv);
        Decrypt(cypherFilePath, decryptedFilePath, key, iv, aes, deleteCypher);
    }

    /// <summary>
    /// Decrypt multiple files
    /// </summary>
    /// <param name="cypherFilePaths">The paths to the files to decrypt</param>
    /// <param name="decryptedFilePaths">The paths to the decrypteds file</param>
    /// <param name="key">The key to use for decryption</param>
    /// <param name="ivs">The IVs to use for decryption</param>
    /// <param name="deleteCypher">True if the cypher file should be deleted, False otherwise</param>
    /// <exception cref="ArgumentException">Thrown if the number of cypher paths, decrypted paths and ivs are different</exception>
    public static void Decrypt(string[] cypherFilePaths, string[] decryptedFilePaths, string key, string[] ivs, bool deleteCypher = false)
    {
        if (cypherFilePaths.Length != decryptedFilePaths.Length)
        {
            throw new ArgumentException("cypherFilePath and decryptedFilePath count mismatch. They must both be of the same length.");
        }
        else if (cypherFilePaths.Length != ivs.Length)
        {
            throw new ArgumentException("cypherFilePath and ivs count mismatch. They must both be of the same length.");
        }
        
        using Aes aes = GetAesInstance(key);
        
        for (int i = 0; i < cypherFilePaths.Length; i++)
        {
            Decrypt(cypherFilePaths[i], decryptedFilePaths[i], key, ivs[i], aes, deleteCypher);
        }
    }

    /// <summary>
    /// Decrypt all files in a given directory
    /// </summary>
    /// <param name="folderPath">The directory to decrypt the files in</param>
    /// <param name="exceptions">A set of folders and files to ignore</param>
    /// <param name="key">The key to use for decryption</param>
    /// <param name="deleteCypher">True if the cypher file should be deleted, False otherwise</param>
    public static void DecryptAll(string folderPath, HashSet<string> exceptions, string key, bool deleteCypher = false)
    {
        Queue<string> paths = new();
        paths.Enqueue(folderPath);

        LinkedList<string> toDecrypt = [];
        LinkedList<string> ivs = [];
        LinkedList<string> ivFiles = [];
        LinkedList<string> decrypted = [];
        while (paths.Count > 0)
        {
            string path = paths.Dequeue();
            // Ignore excepted folders
            if (path.Length > folderPath.Length && exceptions.Contains(path.Substring(folderPath.Length + 1)))
            {
                continue;
            }

            // Add all sub-folders to be processed
            foreach (string dir in Directory.GetDirectories(path))
            {
                paths.Enqueue(dir);
            }

            // Add to the list of files to decrypt
            foreach (string iv in Directory.EnumerateFiles(path, "*.iv"))
            {
                // Ignore excepted files
                string file = iv.Substring(0, iv.Length - 3);
                if (exceptions.Contains(file.Substring(folderPath.Length + 1)))
                {
                    continue;
                }

                toDecrypt.AddLast(file + ".gpg");
                ivs.AddLast(File.ReadAllText(iv));
                ivFiles.AddLast(iv);
                decrypted.AddLast(file);
            }
        }

        Decrypt(toDecrypt.ToArray(), decrypted.ToArray(), key, ivs.ToArray(), deleteCypher);
        
        // Delete IV files
        if (deleteCypher)
        {
            foreach (string iv in ivFiles)
            {
                File.Delete(iv);
            }
        }
    }
}
