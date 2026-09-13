using System.Xml;
using System.Xml.Linq;

namespace Guard.WindowsPoc.Native
{
    internal static class PowerShellStartupProgress
    {
        internal const string Executable = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        internal const int MaximumCharacters = 4096;
        private static readonly XNamespace Namespace = "http://schemas.microsoft.com/powershell/2004/04";

        internal static bool Accepts(string executable, int exitCode, string stderr)
        {
            if (executable != Executable || exitCode != 0) { return false; }
            if (stderr.Length == 0) { return true; }
            if (stderr.Length > MaximumCharacters) { return false; }
            string header = stderr.StartsWith("#< CLIXML\r\n", StringComparison.Ordinal) ? "#< CLIXML\r\n" : "#< CLIXML\n";
            if (!stderr.StartsWith(header, StringComparison.Ordinal)) { return false; }
            try
            {
                using StringReader text = new(stderr[header.Length..]);
                using XmlReader reader = XmlReader.Create(text, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumCharacters });
                XDocument document = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
                XElement? root = document.Root;
                if (document.Declaration is not null || root is null || root.Name != Namespace + "Objs"
                    || !CleanNodes(document) || root.DescendantsAndSelf().Any(element => element.Name.Namespace != Namespace)
                    || root.Attributes().Any(attribute => attribute.IsNamespaceDeclaration ? attribute.Value != Namespace.NamespaceName : attribute.Name != "Version")
                    || (string?)root.Attribute("Version") != "1.1.0.1" || !Children(root, "Obj")) { return false; }
                XElement obj = root.Elements().Single();
                if (!Attributes(obj, "S", "RefId") || (string?)obj.Attribute("S") != "progress" || !ReferenceId(obj) || !Children(obj, "TN", "MS")) { return false; }
                XElement types = obj.Element(Namespace + "TN")!;
                if (!Attributes(types, "RefId") || !ReferenceId(types) || !CleanNodes(types) || types.Elements().Count() != 2
                    || types.Elements().Any(element => element.Name != Namespace + "T" || element.HasAttributes || element.HasElements || !CleanLeaf(element))
                    || !types.Elements().Select(element => element.Value).ToHashSet(StringComparer.Ordinal)
                        .SetEquals(["System.Management.Automation.PSCustomObject", "System.Object"])) { return false; }
                XElement members = obj.Element(Namespace + "MS")!;
                if (members.HasAttributes || !Children(members, "I64", "PR")) { return false; }
                XElement source = members.Element(Namespace + "I64")!;
                XElement progress = members.Element(Namespace + "PR")!;
                if (!Attributes(source, "N") || (string?)source.Attribute("N") != "SourceId" || !CleanLeaf(source) || source.Value != "1"
                    || !Attributes(progress, "N") || (string?)progress.Attribute("N") != "Record"
                    || !Children(progress, "AV", "AI", "Nil", "PI", "PC", "T", "SR", "SD")) { return false; }
                Dictionary<string, string> values = new(StringComparer.Ordinal)
                { ["AV"] = "Preparing modules for first use.", ["AI"] = "0", ["Nil"] = "", ["PI"] = "-1", ["PC"] = "-1", ["T"] = "Completed", ["SR"] = "-1", ["SD"] = " " };
                return progress.Elements().All(element => !element.HasAttributes && CleanLeaf(element) && element.Value == values[element.Name.LocalName]);
            }
            catch (Exception error) when (error is XmlException or InvalidOperationException or ArgumentException) { return false; }
        }

        private static bool ReferenceId(XElement element)
        {
            string? value = (string?)element.Attribute("RefId");
            return value is { Length: > 0 and <= 10 } && value.All(char.IsAsciiDigit);
        }
        private static bool Attributes(XElement element, params string[] names)
        { return element.Attributes().Count() == names.Length && element.Attributes().All(attribute => names.Contains(attribute.Name.ToString(), StringComparer.Ordinal)); }
        private static bool Children(XElement element, params string[] names)
        { return CleanNodes(element) && element.Elements().Count() == names.Length && names.All(name => element.Elements(Namespace + name).Count() == 1); }
        private static bool CleanNodes(XContainer container)
        { return container.Nodes().All(node => node is XElement || (node is XText text && string.IsNullOrWhiteSpace(text.Value))); }
        private static bool CleanLeaf(XElement element)
        { return element.Nodes().All(node => node is XText); }
    }
}
