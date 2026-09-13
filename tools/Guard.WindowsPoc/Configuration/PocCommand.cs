namespace Guard.WindowsPoc.Configuration
{
    internal enum PocCommandKind { Inventory, Run, Recover }

    internal sealed record PocCommand(PocCommandKind Kind)
    {
        internal static PocCommand? Parse(string[] args)
        {
            ArgumentNullException.ThrowIfNull(args);
            return args switch
            {
                ["inventory"] => new(PocCommandKind.Inventory),
                ["run", "--allow-write"] => new(PocCommandKind.Run),
                ["recover", "--allow-write"] => new(PocCommandKind.Recover),
                _ => null
            };
        }
    }
}
