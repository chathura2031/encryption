using System.Reflection;
using Encryption.Core.AES;
using Encryption.FileEncryptor;

AssemblyName assembly = Assembly.GetEntryAssembly().GetName();
Console.WriteLine($"Version {assembly.Version}");

// Get the config
string? input = null;
string configFile = Path.Join(Directory.GetCurrentDirectory(), "config.json");
while (input == null)
{
    Console.Write($"Please enter the path to the config file ({configFile}): ");
    
    input = Console.ReadLine();
    
    if (input == null)
    {
        throw new NotImplementedException();
    }
    else if (input != "")
    {
        configFile = input;
    }
}

// Load the config
Configurations config = Configurations.LoadOrCreate(configFile);
// Load the key
string keyPath = Path.Join(config.WorkingDirectory, config.KeyFile);
string key = FileEncryption.LoadOrGenerateKey(keyPath);

// Present the options
input = "";
while (input != null)
{
    Console.WriteLine("=======================================================");
    Console.WriteLine("1. Encrypt all files");
    Console.WriteLine("2. Decrypt all files");
    Console.WriteLine("3. Rotate key");
    Console.WriteLine("4. Exit");
    Console.Write("Please enter a value corresponding to an option above: ");

    input = Console.ReadLine();
    
    int selection;
    bool success = int.TryParse(input, out selection);
    if (!success || selection < 1 || selection > 4)
    {
        Console.WriteLine("Invalid input. Please try again.\n");
        continue;
    }

    switch (selection)
    {
        case 1:
            FileEncryption.EncryptAll(config.WorkingDirectory, config.Exceptions, key, true);
            Console.WriteLine("All files have been encrypted.\n");
            break;
        case 2:
            FileEncryption.DecryptAll(config.WorkingDirectory, config.Exceptions, key, true);
            Console.WriteLine("All files have been decrypted.\n");
            break;
        case 3:
            key = FileEncryption.RotateKey(config.WorkingDirectory, config.Exceptions, key);
            File.WriteAllText(keyPath, key);
            Console.WriteLine("Key has been rotated and used to encrypt all files.\n");
            break;
        case 4:
            input = null;
            Console.WriteLine("Exiting...");
            break;
    }
}
