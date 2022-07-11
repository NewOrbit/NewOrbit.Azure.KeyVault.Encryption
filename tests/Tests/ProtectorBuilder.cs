namespace NewOrbit.DataProtection.Tests
{
    internal static class ProtectorBuilder
    {
        public static FakeProtector GetProtector()
        {
            return new FakeProtector(new FakeSymmetricKeyWrapper(), new FakeDigestSigner());
        }
    }
}
