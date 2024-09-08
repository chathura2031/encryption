using Newtonsoft.Json;

namespace Encryption.FileEncryptor;

public class Configurations
{
    public string WorkingDirectory { get; set; }
    
    public string KeyFile { get; set; }

    public HashSet<string> Exceptions { get; set; }

    public Configurations(string workingDirectory, string keyFile, string[] exceptions)
    {
        WorkingDirectory = workingDirectory;
        KeyFile = keyFile;
        Exceptions = new();
        Exceptions.UnionWith(exceptions);
    }

    /// <summary>
    /// Load a JSON file containing config data. If one doesn't exist, an empty one will be created and read
    /// </summary>
    /// <param name="path">The path to the JSON file</param>
    /// <returns>A configuration instance with the settings from file</returns>
    /// <exception cref="InvalidOperationException">Thrown if an error is found during parsing</exception>
    public static Configurations LoadOrCreate(string path)
    {
        if (!File.Exists(path))
        {
            File.WriteAllText(path, "{}");
        }
        
        return JsonConvert.DeserializeObject<Configurations>(File.ReadAllText(path)) ?? throw new InvalidOperationException();
    }
}