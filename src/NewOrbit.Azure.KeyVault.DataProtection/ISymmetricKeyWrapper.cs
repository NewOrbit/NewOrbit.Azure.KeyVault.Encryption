namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public interface ISymmetricKeyWrapper
    {
        public void Wrap(byte[] symmetricKey, Span<byte> writeWrappedKeyToThisSpan, Span<byte> writeKeyIdentifierToThisSpan);

        public byte[] UnWrap(in ReadOnlySpan<byte> wrappedKey, in ReadOnlySpan<byte> keyIdentifier);
    }
}