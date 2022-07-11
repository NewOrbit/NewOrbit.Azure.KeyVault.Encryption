namespace NewOrbit.DataProtection.Tests;

using System;
using Shouldly;
using Xunit;

public class SignTests
{
    // Most of the array is signed so modifying most bytes will cause the signature to change.
    // However, changes in other areas will likely cause another exception even if the signing is not working
    // Changes to the payload will not cause an exception unless signing is working.
    private const int SecondEncryptedBytePosition = 306;

    [Fact]
    public void CanDetectTampering()
    {
        var protector = ProtectorBuilder.GetProtector();
        var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 };
        var encrypted = protector.Protect(input);

        var encryptedSecondByte = encrypted[SecondEncryptedBytePosition];

        // Tamper with the second byte of the encrypted data
        encrypted[SecondEncryptedBytePosition] = (encryptedSecondByte < 255) ? (byte)(encryptedSecondByte + 1) : (byte)0;

        // TODO: Change to a specific exception type
        Should.Throw<SignatureValidationException>(() => protector.Unprotect(encrypted));

    }
}
