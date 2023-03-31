using System.Security.Cryptography;

namespace CookieJwtAuth;

public class KeyManager
{
    public KeyManager()
    {
        Rsakey = RSA.Create();
        
        if (File.Exists("Key"))
            Rsakey.ImportRSAPrivateKey(File.ReadAllBytes("Key"), out _);
        else
        {
            var privateKey = Rsakey.ExportRSAPrivateKey();
            File.WriteAllBytes("Key", privateKey);
        }
    }

    public RSA Rsakey { get; }
}