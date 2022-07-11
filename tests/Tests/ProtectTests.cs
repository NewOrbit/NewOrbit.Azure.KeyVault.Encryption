namespace NewOrbit.DataProtection.Tests
{
    using System;
    using Shouldly;
    using Xunit;
    using static ProtectorBuilder;

    public class ProtectTests
    {
        [Fact]
        public void CanProtectAndUnprotect()
        {
            var protector = GetProtector();
            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };

            var encrypted = protector.Encrypt(input).ToByteArray();

            var decrypted = protector.Decrypt(encrypted).ToByteArray();

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
        public void CanProtectAndUnprotectSpecificInputLengths(int inputLength)
        {
            var rng = new Random();
            var protector = GetProtector();
            var input = new byte[inputLength];
            rng.NextBytes(input);

            var encrypted = protector.Encrypt(input).ToByteArray();

            var decrypted = protector.Decrypt(encrypted).ToByteArray();

            decrypted.ShouldBe(input);
        }
    }
}
