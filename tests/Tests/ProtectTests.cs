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

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);
        }

        [Fact]
        public void Temp()
        {
            var protector = GetProtector();
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
        public void CanProtectAndUnprotectSpecificInputLengths(int inputLength)
        {
            var rng = new Random();
            var protector = GetProtector();
            var input = new byte[inputLength];
            rng.NextBytes(input);

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);
        }
    }
}
