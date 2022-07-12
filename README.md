# NewOrbit.Azure.KeyVault.Cryptography

## Suitability
If you just need to encrypt data in your system in a dependable and best-practice way, then this library will do you fine. There are, however, some scenarios that it is less suitable for:

- High Performance: This is not optimised for high performance or for streaming encryption scenarios. The package makes use of Spans and similar approaches to give pretty good performance, but some of the algorithm choices may not be the best choice for high-performance scenarios.  
- Encrypting very large items: The use of Authenticated Encryption requires us to keep all of the encrypted content in memory and the implementation details means the content to be encrypted is usually also kept in memory at the same time.  
- Storage of the encrypted content is at a premium: The "encrypted content" contains two key references, the IV and a signature. All in all, this means a a fixed overhead of 353 bytes is added to the size of the content. For small payloads this is a large increase so this may not be so good if you need to encrypt a very large number of very small items and storage is at a premium.

There are ways you can work around all of these limitations by working closer with the underlying technologies and make a number of choices. For example, you can use the streaming APIs, you may forgo Authenticated Encryption or use the same symmetric key for multiple items. All of these approaches have secrurity implications that you will need to assess for your specific scenario.

## Azure Key Vault
This package relies on Azure Key Vault to encrypt the symmetric key and to sign the hash. It expects two fixed keys in Azure Key Vault - one for the encryption part and one for the 

## Size of the encrypted data
The encrypted data contains all the references and key identifiers it needs to find the correct keys in key vault, validate the signature and decrypt the content.  
That comes with a fixed overhead of 353 bytes. The encrypted content itself has the same size as the input content, except it goes up in 16 byte increments.  
Examples
- Input is 0-15 bytes, the output is 369 bytes
- Input is 16-31 bytes, the output is 385 bytes
- Input is 1 MB (1,048,576 bytes), the output is 1,048,945 bytes.

## Authenticated encryption
..explain what is is...
The approach taken here varies slightly from the canonical implementation. In order to generate the MAC, the library will create a hash of the encrypted content and the IV and use Azure Keyvault to sign and verify this, rather than doing it locally with a another key. 

## Implementation
Span not possible with ICryptoTransform, so having to use `byte[]` in certain places. See [].Net Issue](https://github.com/dotnet/runtime/issues/38764).


