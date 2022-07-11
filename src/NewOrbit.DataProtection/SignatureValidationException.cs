namespace NewOrbit.DataProtection;
using System;

public class SignatureValidationException : DataProtectionException
{
    public SignatureValidationException(string message) : base(message)
    {
    }

    public SignatureValidationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}