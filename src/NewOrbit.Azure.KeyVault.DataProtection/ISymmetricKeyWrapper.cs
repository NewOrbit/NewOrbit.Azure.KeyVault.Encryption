namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public interface ISymmetricKeyWrapper
    {
        public void Wrap(ReadOnlySpan<byte> symmetricKey, Span<byte> writeWrappedKeyToThisSpan, Span<byte> writeKeyIdentifierToThisSpan);

        public byte[] UnWrap(in ReadOnlySpan<byte> wrappedKey, in ReadOnlySpan<byte> keyIdentifier);
    }
}