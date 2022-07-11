namespace NewOrbit.DataProtection;

public class Decryptor
{
    private readonly byte[] encryptedData;
    private readonly ISymmetricKeyWrapper symmetricKeyWrapper;
    private readonly IDigestSigner digestSigner;

    public Decryptor(byte[] encryptedData, ISymmetricKeyWrapper symmetricKeyWrapper, IDigestSigner digestSigner)
    {
        this.encryptedData = encryptedData;
        this.symmetricKeyWrapper = symmetricKeyWrapper;
        this.digestSigner = digestSigner;
    }

    public byte[] ToByteArray()
    {
        var protector = new ProtectorCore(this.symmetricKeyWrapper, this.digestSigner);
        return protector.Unprotect(this.encryptedData);
    }
}