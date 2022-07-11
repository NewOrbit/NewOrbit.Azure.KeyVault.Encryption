namespace NewOrbit.DataProtection;

public class Encryptor
{
    private readonly byte[] data;
    private readonly ISymmetricKeyWrapper symmetricKeyWrapper;
    private readonly IDigestSigner digestSigner;

    public Encryptor(byte[] data, ISymmetricKeyWrapper symmetricKeyWrapper, IDigestSigner digestSigner)
    {
        this.data = data;
        this.symmetricKeyWrapper = symmetricKeyWrapper;
        this.digestSigner = digestSigner;
    }

    public byte[] ToByteArray()
    {
        var protector = new ProtectorCore(this.symmetricKeyWrapper, this.digestSigner);
        return protector.Protect(this.data);
    }
}