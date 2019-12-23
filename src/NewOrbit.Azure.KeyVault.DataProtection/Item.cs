namespace NewOrbit.Azure.KeyVault.DataProtection
{
    public readonly struct Item
    {
        public Item(int position, int length)
        {
            this.Position = position;
            this.Length = length;
        }

        public Item (Item previousItem, int length) 
           : this(previousItem.Position + previousItem.Length, length)
        {}

        public readonly int Position;

        public readonly int Length;
    }
}
