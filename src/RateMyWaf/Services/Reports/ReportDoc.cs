namespace RateMyWaf.Services.Reports;

/// <summary>
/// Renderer-agnostic report content. The same document model drives the on-screen HTML preview and the
/// downloadable Word file, so the preview always matches what the customer receives.
/// </summary>
public sealed class ReportDoc
{
    public string Title { get; init; } = string.Empty;
    public List<ReportBlock> Blocks { get; } = new();

    public ReportDoc H1(string text) { Blocks.Add(new HeadingBlock(1, text)); return this; }
    public ReportDoc H2(string text) { Blocks.Add(new HeadingBlock(2, text)); return this; }
    public ReportDoc P(string text, bool bold = false, string? color = null) { Blocks.Add(new ParaBlock(text, bold, color)); return this; }
    public ReportDoc Note(string text) { Blocks.Add(new NoteBlock(text)); return this; }
    public ReportDoc Bullets(IEnumerable<string> items) { Blocks.Add(new BulletBlock(items.ToList())); return this; }
    public ReportDoc Table(string[]? headers, List<string[]> rows, string emptyText, List<string?[]>? cellColors = null, bool firstColHeader = false)
    { Blocks.Add(new TableBlock(headers, rows, emptyText, cellColors, firstColHeader)); return this; }
    public ReportDoc Grade(string grade, string label, string summary) { Blocks.Add(new GradeBlock(grade, label, summary)); return this; }
    public ReportDoc Legend() { Blocks.Add(new LegendBlock()); return this; }
}

public abstract record ReportBlock;
public sealed record HeadingBlock(int Level, string Text) : ReportBlock;
public sealed record ParaBlock(string Text, bool Bold = false, string? Color = null) : ReportBlock;
public sealed record NoteBlock(string Text) : ReportBlock;
public sealed record BulletBlock(List<string> Items) : ReportBlock;
public sealed record TableBlock(string[]? Headers, List<string[]> Rows, string EmptyText, List<string?[]>? CellColors, bool FirstColHeader) : ReportBlock;
/// <summary>Headline grade tile: big coloured letter, label and a one-line summary.</summary>
public sealed record GradeBlock(string Grade, string Label, string Summary) : ReportBlock;
/// <summary>The full-colour A-F legend.</summary>
public sealed record LegendBlock : ReportBlock;
