namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using System;
    using NewOrbit.Azure.KeyVault.DataProtection;
    using Shouldly;
    using Xunit;

    public class ProtectTests
    {
        [Fact]
        public void CanProtectAndUnprotect()
        {
            var protector = this.GetProtector();
            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);
        }

        [Fact]
        public void Temp()
        {
            var protector = this.GetProtector();
            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 };

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(14)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(1024)]
        [InlineData(1024 * 1024)]
        [InlineData((1024 * 1024) - 1)]
        public void CanProtectAndUprotectSpecificInputLengths(int inputLength)
        {
            var rng = new Random();
            var protector = this.GetProtector();
            var input = new byte[inputLength];
            rng.NextBytes(input);

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);
        }

        private Protector GetProtector()
        {
            return new Protector(new FakeSymmetricKeyWrapper());
        }
    }

    #pragma warning disable SA1402
    public class FakeSymmetricKeyWrapper : ISymmetricKeyWrapper
    {
        private const int SymmetricKeyLengthInBytes = 32;

        private static byte[] staticKeyIdentifier;

        static FakeSymmetricKeyWrapper()
        {
            staticKeyIdentifier = System.Text.Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwxyzABCDEG");
        }

        public void Wrap(byte[] symmetricKey, Span<byte> writeWrappedKeyToThisSpan, Span<byte> writeKeyIdentifierToThisSpan)
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
