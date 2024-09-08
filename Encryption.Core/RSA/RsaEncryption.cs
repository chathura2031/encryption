using System.Security.Cryptography;

namespace Encryption.Core.RSA;


public static class RsaEncryption
{
    /// <summary>
    /// Generate a public and private key pair
    /// </summary>
    /// <returns>The new public and private key pair</returns>
    public static KeyPair GenerateKeys()
    {
        var csp = new RSACryptoServiceProvider(2048);
        
        return new KeyPair
        {
            privateKey = csp.ExportRSAPrivateKeyPem(),
            publicKey = csp.ExportRSAPublicKeyPem()
        };
    }

    /// <summary>
    /// Encrypt some text using a given public key
    /// </summary>
    /// <param name="text">The text to encrypt</param>
    /// <param name="publicKey">The public key to use for encryption</param>
    /// <returns>The encrypted text</returns>
    public static string Encrypt(string text, string publicKey)
    {
        // lets take a new CSP with a new 2048 bit rsa key pair
        var csp = new RSACryptoServiceProvider();
        csp.ImportFromPem(publicKey);

        // for encryption, always handle bytes...
        var textBytes = System.Text.Encoding.Unicode.GetBytes(text);

        // apply pkcs#1.5 padding and encrypt our data 
        var bytesCypherText = csp.Encrypt(textBytes, false);

        // we might want a string representation of our cypher text... base64 will do
        var cypherText = Convert.ToBase64String(bytesCypherText);

        return cypherText;
    }

    /// <summary>
    /// Decrypt some cypher text using a given private key
    /// </summary>
    /// <param name="cypherText">The cypher text to decrypt</param>
    /// <param name="privateKey">The private key to use for decryption</param>
    /// <returns>The decrypted text</returns>
    public static string Decrypt(string cypherText, string privateKey)
    {
        // first, get our bytes back from the base64 string ...
        var bytesCypherText = Convert.FromBase64String(cypherText);

        // we want to decrypt, therefore we need a csp and load our private key
        var csp = new RSACryptoServiceProvider();
        csp.ImportFromPem(privateKey);

        // decrypt and strip pkcs#1.5 padding
        var cypherTextBytes = csp.Decrypt(bytesCypherText, false);

        // get our original plainText back...
        var text = System.Text.Encoding.Unicode.GetString(cypherTextBytes);

        return text;
    }
}
