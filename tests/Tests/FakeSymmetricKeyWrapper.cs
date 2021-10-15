namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using System;
    using NewOrbit.Azure.KeyVault.DataProtection;
    using Shouldly;
#pragma warning disable SA1402
    public class FakeSymmetricKeyWrapper : ISymmetricKeyWrapper
    {
        private const int SymmetricKeyLengthInBytes = 32;

        private static byte[] staticKeyIdentifier;

        static FakeSymmetricKeyWrapper()
        {
            staticKeyIdentifier = System.Text.Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyzABCDEG");
        }

        public void Wrap(ReadOnlySpan<byte> symmetricKey, Span<byte> writeWrappedKeyToThisSpan, Span<byte> writeKeyIdentifierToThisSpan)
        {
            symmetricKey.Length.ShouldBe(SymmetricKeyLengthInBytes);
            symmetricKey.CopyTo(writeWrappedKeyToThisSpan);
            writeWrappedKeyToThisSpan.Reverse();
            staticKeyIdentifier.CopyTo(writeKeyIdentifierToThisSpan);
        }

        public byte[] UnWrap(in ReadOnlySpan<byte> wrappedKey, in ReadOnlySpan<byte> keyIdentifier)
        {
            wrappedKey.Length.ShouldBe(Constants.RSAKeySize / 8);
            keyIdentifier.ToArray().ShouldBe(staticKeyIdentifier);
            var output = new byte[SymmetricKeyLengthInBytes];
            var temp = wrappedKey.ToArray();
            Array.Reverse(temp);
            temp.AsSpan().Slice(0, SymmetricKeyLengthInBytes).CopyTo(output);

            return output;
        }
    }
}
