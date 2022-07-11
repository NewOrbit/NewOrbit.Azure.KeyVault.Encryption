namespace NewOrbit.DataProtection;
using System;

public abstract class DataProtectionException : Exception
{
    protected DataProtectionException(string message) : base(message)
    {
    }

    protected DataProtectionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}