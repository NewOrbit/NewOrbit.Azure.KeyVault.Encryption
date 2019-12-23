namespace NewOrbit.Azure.KeyVault.DataProtection
{
    using System;

    public readonly struct Item : IEquatable<Item>
    {
        public readonly int Position;

        public readonly int Length;

        public Item(int position, int length)
        {
            this.Position = position;
            this.Length = length;
        }

        public Item(Item previousItem, int length)
           : this(previousItem.Position + previousItem.Length, length)
        {
        }

        public static bool operator ==(Item left, Item right) => left.Equals(right);

        public static bool operator !=(Item left, Item right) => !left.Equals(right);

        public bool Equals(Item other) => other.Position == this.Position && other.Length == this.Length;

        public override bool Equals(object other) => other is Item o && this.Equals(o);

        public override int GetHashCode() => this.Length * this.Position;
    }
}
