namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using NewOrbit.Azure.KeyVault.DataProtection;
    using Shouldly;
    using Xunit;

    public class ProtectTests
    {
        [Fact]
        public void CanProtectAndUnprotect()
        {
            var protector = new Protector();
            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };

            var encrypted = protector.Protect(input);

            var decrypted = protector.Unprotect(encrypted);

            decrypted.ShouldBe(input);

        }
    }
}
