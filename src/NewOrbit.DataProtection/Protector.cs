namespace NewOrbit.DataProtection;
using System;
using System.Text;

public abstract class Protector
{
    private readonly ISymmetricKeyWrapper symmetricKeyWrapper;
    private readonly IDigestSigner digestSigner;

    protected Protector(ISymmetricKeyWrapper symmetricKeyWrapper, IDigestSigner digestSigner)
    {
        this.symmetricKeyWrapper = symmetricKeyWrapper;
        this.digestSigner = digestSigner;
    }

    public Encryptor Encrypt(byte[] data)
    {
        return new Encryptor(data, this.symmetricKeyWrapper, this.digestSigner);
    }

    public Encryptor Encrypt(string data) => this.Encrypt(data, Encoding.UTF8);

    public Encryptor Encrypt(string data, Encoding encoding)
    {
        throw new NotImplementedException();
    }

    public Decryptor Decrypt(byte[] encryptedData)
    {
        return new Decryptor(encryptedData, this.symmetricKeyWrapper, this.digestSigner);
    }
}