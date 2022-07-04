namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using System;
    using System.Security;
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
            var sud = ArrayPositionsV1.Get(contentLength);
            sud.EncryptedContent.Length.ShouldBe(encryptedLength);
        }

        [Fact]
        public void CalculateCorrectPositions()
        {
            var sud = ArrayPositionsV1.Get(16);

            sud.Version.Position.ShouldBe(0);
            sud.AsymmetricWrapperKeyIdentifier.Position.ShouldBe(1);
            sud.WrappedSymmetricKey.Position.ShouldBe(33);
            sud.InitialisationVector.Position.ShouldBe(289);
            sud.EncryptedContent.Position.ShouldBe(305);
            sud.EncryptedContent.Length.ShouldBe(32);
            sud.SigningKeyIdentifier.Position.ShouldBe(337);
            sud.Signature.Position.ShouldBe(369);
            sud.Signature.Length.ShouldBe(128 / 8); // Only keep 128 bits of the signature as per "Security Driven .Net"
            sud.TotalLength.ShouldBe(385);
        }

        [Fact]
        public void CalculateCorrectPositionsForEncrypted()
        {
            Span<byte> encrypted = new byte[385];
            var sud = ArrayPositionsV1.Get(encrypted);

            sud.Version.Position.ShouldBe(0);
            sud.AsymmetricWrapperKeyIdentifier.Position.ShouldBe(1);
            sud.WrappedSymmetricKey.Position.ShouldBe(33);
            sud.InitialisationVector.Position.ShouldBe(289);
            sud.EncryptedContent.Position.ShouldBe(305);
            sud.EncryptedContent.Length.ShouldBe(32);
            sud.SigningKeyIdentifier.Position.ShouldBe(337);
            sud.Signature.Position.ShouldBe(369);
            sud.Signature.Length.ShouldBe(128 / 8); // Only keep 128 bits of the signature as per "Security Driven .Net"
            sud.TotalLength.ShouldBe(385);
        }

        [Theory]
        [InlineData(0, 369)]
        [InlineData(15, 369)]
        [InlineData(16, 385)]
        [InlineData(31, 385)]
        [InlineData(1_048_576, 1_048_945)]

        public void CalculateContentLengths(int contentLength, int outputLength)
        {
            var sud = ArrayPositionsV1.Get(contentLength);
            sud.TotalLength.ShouldBe(outputLength);
        }


        [Fact]
        public void ShouldThrowIfEncryptedContentIsTooShort()
        {
            ArgumentException thrownException = null;

            Span<byte> encrypted = new byte[353];
            try
            {
                var sud = ArrayPositionsV1.Get(encrypted);
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
                var sud = ArrayPositionsV1.Get(encrypted);
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