namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public interface ISymmetricKeyWrapper
    {
        public void Wrap(byte[] symmetricKey, Span<byte> writeWrappedKeyToThisSpan);

        public byte[] UnWrap(in ReadOnlySpan<byte> wrappedKey);
    }
}