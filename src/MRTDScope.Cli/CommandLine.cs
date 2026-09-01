namespace MRTDScope.Cli;

/// <summary>
/// A deliberately small option parser.
/// </summary>
/// <remarks>
/// Enough for <c>--name value</c> and <c>--flag</c>, and nothing more. A command-line
/// framework would be a dependency carried for one command, and this tool's surface is
/// small enough that the trade does not pay.
/// <para>
/// Unknown options are rejected rather than ignored. A mistyped <c>--truts</c> that is
/// silently discarded means the inspection runs with no trust anchors and reports the
/// certificate chain as inconclusive, which looks like a fact about the document.
/// </para>
/// </remarks>
internal sealed class CommandLine
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.Ordinal);
    private readonly List<string> _positional = [];

    private CommandLine()
    {
    }

    /// <summary>Positional arguments, in order, excluding the command itself.</summary>
    public IReadOnlyList<string> Positional => _positional;

    /// <summary>
    /// Parses arguments against the set of options a command accepts.
    /// </summary>
    /// <param name="args">Arguments, excluding the command name.</param>
    /// <param name="valueOptions">Options taking a value, without the leading dashes.</param>
    /// <param name="flags">Options taking no value, without the leading dashes.</param>
    /// <param name="error">What was wrong, when parsing failed.</param>
    public static CommandLine? TryParse(
        IReadOnlyList<string> args,
        IReadOnlyCollection<string> valueOptions,
        IReadOnlyCollection<string> flags,
        out string error)
    {
        CommandLine parsed = new();
        error = string.Empty;

        HashSet<string> takesValue = new(valueOptions, StringComparer.Ordinal);
        HashSet<string> isFlag = new(flags, StringComparer.Ordinal);

        for (int i = 0; i < args.Count; i++)
        {
            string argument = args[i];

            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                parsed._positional.Add(argument);
                continue;
            }

            string name = argument[2..];

            if (isFlag.Contains(name))
            {
                parsed._options[name] = null;
                continue;
            }

            if (!takesValue.Contains(name))
            {
                error = $"Unknown option '--{name}'.";
                return null;
            }

            if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                error = $"Option '--{name}' needs a value.";
                return null;
            }

            parsed._options[name] = args[++i];
        }

        return parsed;
    }

    /// <summary>The value of an option, or null when it was not given.</summary>
    public string? Value(string name) =>
        _options.TryGetValue(name, out string? value) ? value : null;

    /// <summary>Whether a flag or option was present at all.</summary>
    public bool Has(string name) => _options.ContainsKey(name);
}
