using CommandLine;
using Action = Encryption.FileEncryptor.Enums.Action;

namespace Encryption.FileEncryptor;

public class CliOptions
{
    [Option('w', "workingdir", Required = false,
        HelpText = "the directory to work from")]
    public string? WorkingDir { get; set; }
    
    [Option('a', "action", Required = false,
        HelpText = "the action to perform (either EncryptAll, DecryptAll or RotateKey)")]
    public Action? Action { get; set; }
    
    [Option('f', Required = false,
        HelpText = "whether to exit if the key file is not found")]
    public bool FailIfKeyNotFound { get; set; }
}