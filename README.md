# NewOrbit.Azure.KeyVault.Cryptography

## Size of the encrypted data
The encrypted data contains all the references and key identifiers it needs to find the correct keys in key vault, validate the signature and decrypt the content.  
That comes with a fixed overhead of 353 bytes. The encrypted content itself has the same size as the input content, except it goes up in 16 byte increments.  
Examples
- Input is 0-15 bytes, the output is 369 bytes
- Input is 16-31 bytes, the output is 385 bytes
- Input is 1 MB (1,048,576 bytes), the output is 1,048,945 bytes.

