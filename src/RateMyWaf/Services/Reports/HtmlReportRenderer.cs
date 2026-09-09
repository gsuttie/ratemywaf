using System.Net;
using System.Text;

namespace RateMyWaf.Services.Reports;

/// <summary>Renders a ReportDoc as self-contained HTML for the in-app preview.</summary>
public static class HtmlReportRenderer
{
    private const string Accent = "#2563EB";

    public static string Render(ReportDoc doc)
    {
        var sb = new StringBuilder();
        sb.Append($"<h1 style='color:{Accent};font-weight:700;margin:0 0 12pt 0;'>{E(doc.Title)}</h1>");
        foreach (var block in doc.Blocks)
            sb.Append(Render(block));
        return sb.ToString();
    }

    private static string Render(ReportBlock block) => block switch
    {
        HeadingBlock h => h.Level == 1
            ? $"<h2 style='color:{Accent};font-weight:700;margin:16pt 0 6pt 0;'>{E(h.Text)}</h2>"
            : $"<h3 style='color:{Accent};font-weight:600;margin:12pt 0 4pt 0;'>{E(h.Text)}</h3>",
        ParaBlock p => $"<p style='font-size:10.5pt;margin:0 0 8pt 0;'>{ParaHtml(p)}</p>",
        NoteBlock n => $"<p style='font-size:9.5pt;color:#666;font-style:italic;margin:0 0 8pt 0;'>{E(n.Text)}</p>",
        BulletBlock b => $"<ul style='margin:4pt 0 8pt 0.5cm;'>{string.Concat(b.Items.Select(i => $"<li style='font-size:10.5pt;margin-bottom:3pt;'>{E(i)}</li>"))}</ul>",
        TableBlock t => t.Rows.Count == 0 ? $"<p style='font-size:10.5pt;margin:0 0 8pt 0;'><i>{E(t.EmptyText)}</i></p>" : Table(t),
        GradeBlock g => Grade(g),
        LegendBlock => string.Concat(WafRatingService.Legend.Select(LegendRow)),
        _ => ""
    };

    private static string ParaHtml(ParaBlock p)
    {
        var html = E(p.Text).Replace("\n", "<br/>");
        if (p.Bold) html = $"<strong>{html}</strong>";
        if (p.Color is not null) html = $"<span style='color:{p.Color};'>{html}</span>";
        return html;
    }

    private static string Grade(GradeBlock g)
    {
        var color = WafRatingService.ColorForGrade(g.Grade);
        return
            $"<div style='display:flex;align-items:center;gap:14px;margin:6pt 0 10pt 0;'>" +
            $"<span style='display:inline-flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:12px;background:{color};color:#fff;font-weight:800;font-size:26pt;'>{E(g.Grade)}</span>" +
            $"<div><div style='color:{color};font-weight:700;font-size:13pt;'>{E(g.Label)}</div><div style='font-size:10.5pt;'>{E(g.Summary)}</div></div></div>";
    }

    private static string LegendRow((string Grade, string Label, string Description) item)
    {
        var color = WafRatingService.ColorForGrade(item.Grade);
        return
            $"<div style='display:flex;align-items:center;gap:10px;background:{color}1A;border-radius:8px;padding:6px 10px;margin:0 0 5px 0;'>" +
            $"<span style='display:inline-flex;align-items:center;justify-content:center;min-width:30px;height:30px;border-radius:6px;background:{color};color:#fff;font-weight:800;font-size:13pt;'>{E(item.Grade)}</span>" +
            $"<span><span style='color:{color};font-weight:bold;font-size:10.5pt;'>{E(item.Label)}</span><br/><span style='font-size:10pt;'>{E(item.Description)}</span></span></div>";
    }

    private static string Table(TableBlock t)
    {
        var sb = new StringBuilder("<table style='border-collapse:collapse;width:100%;margin:6pt 0 12pt 0;'>");
        if (t.Headers is { Length: > 0 })
        {
            sb.Append("<tr>");
            foreach (var h in t.Headers)
                sb.Append($"<th style='background-color:{Accent};color:#fff;font-size:10.5pt;padding:4pt 6pt;border:1px solid #ddd;text-align:left;'>{E(h)}</th>");
            sb.Append("</tr>");
        }
        for (var r = 0; r < t.Rows.Count; r++)
        {
            var colors = t.CellColors is not null && r < t.CellColors.Count ? t.CellColors[r] : null;
            sb.Append("<tr>");
            for (var i = 0; i < t.Rows[r].Length; i++)
            {
                var style = t.FirstColHeader && i == 0 ? $"background-color:{Accent};color:#fff;font-weight:bold;width:180px;" : "";
                if (colors is not null && i < colors.Length && colors[i] is { } c) style += $"color:{c};font-weight:bold;";
                sb.Append($"<td style='font-size:10.5pt;padding:4pt 6pt;border:1px solid #ddd;vertical-align:top;{style}'>{E(t.Rows[r][i]).Replace("\n", "<br/>")}</td>");
            }
            sb.Append("</tr>");
        }
        sb.Append("</table>");
        return sb.ToString();
    }

    private static string E(string s) => WebUtility.HtmlEncode(s);
}
