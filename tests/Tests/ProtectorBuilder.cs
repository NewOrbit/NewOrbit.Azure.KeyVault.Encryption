namespace NewOrbit.Azure.KeyVault.DataProtection.Tests
{
    using System;
    using System.Security.Cryptography;
    using Moq;
    using NewOrbit.Azure.KeyVault.DataProtection;
    using Shouldly;
    using Xunit;
    using static ProtectorBuilder;

    internal static class ProtectorBuilder
    {
        public static Protector GetProtector()
        {
            // Note that we can't (easily) use Moq as Span can't be used as a type parameter

            // TODO: Allow to pass in key identifiers and check they are being written correctly to the output
            // TODO: Allow to pass in a particular signature and check it is being written correctly to the output
            // TODO: Allow to set it to fail the signature validation and test
            // TODO: Allow to pass in a specific "encrypted content" in order to test it being written correctly to the output
            return new Protector(new FakeSymmetricKeyWrapper(), new FakeDigestSigner());
        }
    }
}
