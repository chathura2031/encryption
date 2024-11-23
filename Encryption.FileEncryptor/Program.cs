using System.Reflection;
using CommandLine;
using Encryption.Core.AES;
using Encryption.FileEncryptor;
using Action = Encryption.FileEncryptor.Enums.Action;

AssemblyName assembly = Assembly.GetEntryAssembly().GetName();
Console.WriteLine($"Version {assembly.Version}");

string workingDir = Directory.GetCurrentDirectory();
Action? action = null;
bool usingDefaultWorkingDir = true;
bool failIfKeyNotFound = false;

var result = Parser.Default.ParseArguments<CliOptions>(args)
    .WithParsed<CliOptions>(options =>
    {
        if (options.WorkingDir != null)
        {
            workingDir = options.WorkingDir;
            action = options.Action;
            failIfKeyNotFound = options.FailIfKeyNotFound;
            usingDefaultWorkingDir = false;
        }
    });

bool validCliArgs = !result.Errors.Any();
if (!validCliArgs)
{
    return 1;
}

// Get the config
string configFile = Path.Join(workingDir, "config.json");
string? input;
if (!File.Exists(configFile))
{
    input = null;
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
}

// Load the config
if (!File.Exists(configFile))
{
    Console.WriteLine($"Config file at {configFile} could not be found. Creating empty config file.");
}
Configurations config = Configurations.LoadOrCreate(configFile);

// Get the working directory
// ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
if (usingDefaultWorkingDir && config.WorkingDirectory == null)
{
    input = null;
    while (input == null)
    {
        Console.Write($"Please enter the path to the working directory ({workingDir}): ");
        
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
}
else if (usingDefaultWorkingDir)
{
    workingDir = config.WorkingDirectory;
}

// Load the key
string keyPath = Path.Join(workingDir, config.KeyFile);
if (!File.Exists(keyPath))
{
    if (failIfKeyNotFound)
    {
        Console.WriteLine($"Key file at {keyPath} could not be found. Exiting.");
        return 1;
    }
    else
    {
        Console.WriteLine($"Key file at {keyPath} could not be found. Generating a new key file.");
    }
}
string key = FileEncryption.LoadOrGenerateKey(keyPath);

// Present the options
KeyValuePair<Action, string>[] options = [
    new(Action.EncryptAll, "Encrypt all files"),
    new(Action.DecryptAll, "Decrypt all files"),
    new(Action.RotateKey, "Rotate key"),
    new(Action.Exit, "Exit"),
];

if (action == null)
{
    input = "";
    while (input != null)
    {
        Console.WriteLine("=======================================================");
        for (int i = 0; i < options.Length; i++)
        {
            Console.WriteLine($"{i+1}. {options[i].Value}");
        }
        Console.Write("Please enter a value corresponding to an option above: ");

        input = Console.ReadLine();

        bool success = int.TryParse(input, out var selection);
        if (!success || selection < 1 || selection > options.Length)
        {
            Console.WriteLine("Invalid input. Please try again.\n");
            continue;
        }

        ProcessAction(options[selection-1].Key);
    }
}
else
{
    ProcessAction((Action)action);
}

void ProcessAction(Action action)
{
    switch (action)
    {
        case Action.EncryptAll:
        {
            FileEncryption.EncryptAll(workingDir, config.Exceptions, key, true);
            Console.WriteLine("All files have been encrypted.\n");
            break;
        }
        case Action.DecryptAll:
        {
            FileEncryption.DecryptAll(workingDir, config.Exceptions, key, true);
            Console.WriteLine("All files have been decrypted.\n");
            break;
        }
        case Action.RotateKey:
        {
            key = FileEncryption.RotateKey(workingDir, config.Exceptions, key);
            File.WriteAllText(keyPath, key);
            Console.WriteLine("Key has been rotated and used to encrypt all files.\n");
            break;
        }
        case Action.Exit:
        {
            input = null;
            Console.WriteLine("Exiting...");
            break;
        }
        default:
            throw new NotImplementedException();
    }
}

return 0;
