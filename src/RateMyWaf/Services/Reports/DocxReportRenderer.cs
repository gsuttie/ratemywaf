using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;

namespace RateMyWaf.Services.Reports;

/// <summary>Renders a ReportDoc as a Word document (no template required).</summary>
public static class DocxReportRenderer
{
    private const string Accent = "2563EB";

    public static byte[] Render(ReportDoc doc)
    {
        using var stream = new MemoryStream();
        using (var word = WordprocessingDocument.Create(stream, WordprocessingDocumentType.Document))
        {
            var main = word.AddMainDocumentPart();
            main.Document = new Document(new Body());
            var body = main.Document.Body!;

            body.Append(Paragraph(doc.Title, size: 40, bold: true, color: Accent, spacingAfter: 240));
            foreach (var block in doc.Blocks)
                foreach (var el in Render(block))
                    body.Append(el);

            body.Append(new SectionProperties(
                new PageMargin { Top = 1134, Right = 1134, Bottom = 1134, Left = 1134, Header = 708, Footer = 708, Gutter = 0 }));
            main.Document.Save();
        }
        return stream.ToArray();
    }

    private static IEnumerable<OpenXmlElement> Render(ReportBlock block)
    {
        switch (block)
        {
            case HeadingBlock h:
                yield return Paragraph(h.Text, size: h.Level == 1 ? 30 : 24, bold: true, color: Accent, spacingBefore: h.Level == 1 ? 320 : 200, spacingAfter: 100, keepNext: true);
                break;
            case ParaBlock p:
                yield return Paragraph(p.Text, bold: p.Bold, color: p.Color?.TrimStart('#'));
                break;
            case NoteBlock n:
                yield return Paragraph(n.Text, size: 19, italic: true, color: "666666");
                break;
            case BulletBlock b:
                foreach (var item in b.Items)
                    yield return Paragraph("• " + item, indentLeft: 360, spacingAfter: 60);
                break;
            case GradeBlock g:
            {
                var hex = WafRatingService.ColorForGrade(g.Grade).TrimStart('#');
                var para = new Paragraph(new ParagraphProperties(new SpacingBetweenLines { After = "160" }));
                para.Append(new Run(new Text($"  {g.Grade}  ") { Space = SpaceProcessingModeValues.Preserve })
                {
                    RunProperties = new RunProperties(new Bold(), new Color { Val = "FFFFFF" }, new FontSize { Val = "40" },
                        new Shading { Val = ShadingPatternValues.Clear, Fill = hex })
                });
                para.Append(new Run(new Text($"  {g.Label}") { Space = SpaceProcessingModeValues.Preserve })
                {
                    RunProperties = new RunProperties(new Bold(), new Color { Val = hex }, new FontSize { Val = "28" })
                });
                yield return para;
                yield return Paragraph(g.Summary);
                break;
            }
            case LegendBlock:
                foreach (var (grade, label, description) in WafRatingService.Legend)
                {
                    var hex = WafRatingService.ColorForGrade(grade).TrimStart('#');
                    var para = new Paragraph(new ParagraphProperties(new SpacingBetweenLines { After = "80" }));
                    para.Append(new Run(new Text($"  {grade}  ") { Space = SpaceProcessingModeValues.Preserve })
                    {
                        RunProperties = new RunProperties(new Bold(), new Color { Val = "FFFFFF" },
                            new Shading { Val = ShadingPatternValues.Clear, Fill = hex })
                    });
                    para.Append(new Run(new Text($"  {label}: ") { Space = SpaceProcessingModeValues.Preserve })
                    {
                        RunProperties = new RunProperties(new Bold(), new Color { Val = hex })
                    });
                    para.Append(new Run(new Text(description) { Space = SpaceProcessingModeValues.Preserve }));
                    yield return para;
                }
                break;
            case TableBlock t:
                if (t.Rows.Count == 0)
                    yield return Paragraph(t.EmptyText, italic: true);
                else
                    yield return Table(t);
                yield return Paragraph("", spacingAfter: 60);
                break;
        }
    }

    private static Table Table(TableBlock t)
    {
        var table = new Table(new TableProperties(
            new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct },
            new TableBorders(
                new TopBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" },
                new BottomBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" },
                new LeftBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" },
                new RightBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" },
                new InsideHorizontalBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" },
                new InsideVerticalBorder { Val = BorderValues.Single, Size = 4, Color = "CCCCCC" })));

        if (t.Headers is { Length: > 0 })
        {
            var header = new TableRow(new TableRowProperties(new TableHeader()));
            foreach (var h in t.Headers)
                header.Append(Cell(h, bold: true, color: "FFFFFF", fill: Accent));
            table.Append(header);
        }

        for (var r = 0; r < t.Rows.Count; r++)
        {
            var colors = t.CellColors is not null && r < t.CellColors.Count ? t.CellColors[r] : null;
            var row = new TableRow();
            for (var i = 0; i < t.Rows[r].Length; i++)
            {
                var isHeaderCol = t.FirstColHeader && i == 0;
                var color = colors is not null && i < colors.Length ? colors[i]?.TrimStart('#') : null;
                row.Append(Cell(t.Rows[r][i],
                    bold: isHeaderCol || color is not null,
                    color: isHeaderCol ? "FFFFFF" : color,
                    fill: isHeaderCol ? Accent : null));
            }
            table.Append(row);
        }
        return table;
    }

    private static TableCell Cell(string text, bool bold = false, string? color = null, string? fill = null)
    {
        var props = new TableCellProperties(new TableCellMargin(
            new LeftMargin { Width = "80", Type = TableWidthUnitValues.Dxa },
            new RightMargin { Width = "80", Type = TableWidthUnitValues.Dxa }));
        if (fill is not null) props.Append(new Shading { Val = ShadingPatternValues.Clear, Fill = fill });
        var cell = new TableCell(props);
        cell.Append(Paragraph(text, size: 19, bold: bold, color: color, spacingAfter: 40, spacingBefore: 40));
        return cell;
    }

    private static Paragraph Paragraph(string text, int size = 21, bool bold = false, bool italic = false, string? color = null,
        int spacingBefore = 0, int spacingAfter = 120, int indentLeft = 0, bool keepNext = false)
    {
        var pPr = new ParagraphProperties(new SpacingBetweenLines { Before = spacingBefore.ToString(), After = spacingAfter.ToString() });
        if (indentLeft > 0) pPr.Append(new Indentation { Left = indentLeft.ToString() });
        if (keepNext) pPr.Append(new KeepNext());
        var para = new Paragraph(pPr);

        var rPr = new RunProperties(new RunFonts { Ascii = "Calibri", HighAnsi = "Calibri" }, new FontSize { Val = size.ToString() });
        if (bold) rPr.Append(new Bold());
        if (italic) rPr.Append(new Italic());
        if (color is not null) rPr.Append(new Color { Val = color });

        var run = new Run(rPr);
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            run.Append(new Text(lines[i]) { Space = SpaceProcessingModeValues.Preserve });
            if (i < lines.Length - 1) run.Append(new Break());
        }
        para.Append(run);
        return para;
    }
}
