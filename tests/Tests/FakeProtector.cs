namespace NewOrbit.DataProtection.Tests;

public class FakeProtector : Protector
{
    public FakeProtector(ISymmetricKeyWrapper symmetricKeyWrapper, IDigestSigner digestSigner) : base(symmetricKeyWrapper, digestSigner)
    {
    }
}
