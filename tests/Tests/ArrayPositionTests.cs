namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using System;
    using Shouldly;
    using Xunit;

    public class ArrayPositionTests
    {
        [Theory]
        [InlineData(0, 16)]
        [InlineData(1, 16)]
        [InlineData(15, 16)]
        [InlineData(16, 32)]
        [InlineData(17, 32)]
        public void CalculateContentLength(int contentLength, int encryptedLength)
        {
            var sud = new ArrayPositionsV1(contentLength);
            sud.EncryptedContent.Length.ShouldBe(encryptedLength);
        }

        [Fact]
        public void CalculateCorrectPositions()
        {
            var sud = new ArrayPositionsV1(16);

            sud.Version.Position.ShouldBe(0);
            sud.EncryptingKeyVersion.Position.ShouldBe(1);
            sud.EncryptingKey.Position.ShouldBe(33);
            sud.InitialisationVector.Position.ShouldBe(289);
            sud.EncryptedContent.Position.ShouldBe(305);
            sud.EncryptedContent.Length.ShouldBe(32);
            sud.SigningKeyVersion.Position.ShouldBe(337);
            sud.Signature.Position.ShouldBe(369);
            sud.TotalLength.ShouldBe(625);
        }

        [Fact]
        public void CalculateCorrectPositionsForEncrypted()
        {
            Span<byte> encrypted = new byte[625];
            var sud = new ArrayPositionsV1(encrypted);

            sud.Version.Position.ShouldBe(0);
            sud.EncryptingKeyVersion.Position.ShouldBe(1);
            sud.EncryptingKey.Position.ShouldBe(33);
            sud.InitialisationVector.Position.ShouldBe(289);
            sud.EncryptedContent.Position.ShouldBe(305);
            sud.EncryptedContent.Length.ShouldBe(32);
            sud.SigningKeyVersion.Position.ShouldBe(337);
            sud.Signature.Position.ShouldBe(369);
            sud.TotalLength.ShouldBe(625);
        }

        [Fact]
        public void ShouldThrowIfEncryptedContentIsTooShort()
        {
            ArgumentException thrownException = null;

            Span<byte> encrypted = new byte[593];
            try
            {
                var sud = new ArrayPositionsV1(encrypted);
            }
            catch (ArgumentException e)
            {
                thrownException = e;
            }

            thrownException.ShouldNotBeNull();

            // Can't use Should.Throw because Spans and Lambdas don't play nice
        }

        [Fact]
        public void ShouldThrowIfEncryptedContentIsNotMultipleOf16()
        {
            ArgumentException thrownException = null;

            Span<byte> encrypted = new byte[626];
            try
            {
                var sud = new ArrayPositionsV1(encrypted);
            }
            catch (ArgumentException e)
            {
                thrownException = e;
            }

            thrownException.ShouldNotBeNull();

            // Can't use Should.Throw because Spans and Lambdas don't play nice
        }
    }
}