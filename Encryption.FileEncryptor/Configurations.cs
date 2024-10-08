using Newtonsoft.Json;

namespace Encryption.FileEncryptor;

public class Configurations
{
    [JsonProperty(Required = Required.Default)]
    public string WorkingDirectory { get; private set; }
    
    [JsonProperty(Required = Required.Always)]
    public string KeyFile { get; private set; }

    [JsonProperty(Required = Required.Always)]
    public HashSet<string> Exceptions { get; private set; }

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
            File.WriteAllText(path, "{\"keyFile\": \"key\", \"exceptions\": [\"key\", \"config.json\"]}");
        }
        
        return JsonConvert.DeserializeObject<Configurations>(File.ReadAllText(path)) ?? throw new InvalidOperationException();
    }
}