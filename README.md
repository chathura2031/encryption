# Core
This project contains functions for RSA string encryption and AES file encryption

# File Encryptor
This projects contains a file encryptor which uses the core library to encrypt or decrypt 
all files in a given directory. It relies on a json type config file with the following 
properties:

| Key                | Description                                                                          | Type         | Required |
|--------------------|--------------------------------------------------------------------------------------|--------------|----------|
| `workingDirectory` | The desired working directory. File to encrypt and decrypt must be in this directory | string       | No       |
| `keyFile`          | The path to the key file relative to the `workingDirectory`                          | string       | Yes      |
| `exceptions`       | A list of folders and files to ignore when encrypting and decrypting                 | List[string] | Yes      |

### Sample config file
```json
{
  "workingDirectory": "/home/bob/Documents",
  "keyFile": "key",
  "exceptions": [
    "key",
    "config.json"
  ]
}
```