package ledgerguard

import (
	"encoding/json"
	"html/template"
	"io"
	"sort"
	"strings"
)

// WriteJSON writes the machine-readable report.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type controlRow struct {
	Control
	Findings []string
}

// ControlMatrix groups findings by the control they break, which is the view a
// CISO or auditor reads first.
func (r *Report) ControlMatrix() []controlRow {
	idx := map[string]*controlRow{}
	var order []string
	for _, f := range r.Findings {
		for _, c := range f.Controls {
			k := c.Framework + "|" + c.Ref
			row, ok := idx[k]
			if !ok {
				row = &controlRow{Control: c}
				idx[k] = row
				order = append(order, k)
			}
			row.Findings = append(row.Findings, f.ID)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i] < order[j] })
	out := make([]controlRow, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	return out
}

// WriteHTML writes the board-ready, self-contained HTML report.
func (r *Report) WriteHTML(w io.Writer) error {
	return reportTmpl.Execute(w, r)
}

var reportTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"money": func(v int64) string { return Money(v, "INR") },
	"upper": strings.ToUpper,
	"ts":    func(t interface{ Format(string) string }) string { return t.Format("2006-01-02 15:04:05 MST") },
}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LedgerGuard Report</title>
<style>
:root{--bg:#f7f7f8;--fg:#15161a;--mut:#5b5f6a;--card:#fff;--line:#e3e4e8;--crit:#c0262d;--high:#d9631e;--ok:#1f8a4c;--acc:#5b2fd1}
@media (prefers-color-scheme:dark){:root{--bg:#0f1014;--fg:#ececf1;--mut:#9aa0ad;--card:#181a20;--line:#2a2d36;--acc:#9d7bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:26px;margin:0}h2{font-size:18px;margin:32px 0 12px}.mut{color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}.kpi b{display:block;font-size:26px}
.grade{font-size:40px!important;color:var(--acc)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}th{color:var(--mut);font-weight:600}
.sev{font-weight:700;font-size:12px;padding:2px 8px;border-radius:99px;color:#fff}.critical{background:var(--crit)}.high{background:var(--high)}.pass{background:var(--ok)}
.f{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
.f h3{margin:0 0 6px;font-size:16px}details{margin-top:10px}pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12px;max-height:280px;overflow:auto}
.tag{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:1px 7px;margin:2px 4px 2px 0;font-size:12px}
.wrap{overflow-x:auto}
</style></head><body><main>
<div class="mut">ARTEX · LedgerGuard money-invariant assurance</div>
<h1>{{.Target}}</h1>
<div class="mut">{{.BaseURL}} · engagement <b>{{.Authorization}}</b> · {{ts .StartedAt}}</div>
<div class="kpis">
<div class="kpi"><span class="mut">Resilience grade</span><b class="grade">{{.Grade}}</b><span class="mut">{{.Score}}/100</span></div>
<div class="kpi"><span class="mut">Invariant breaks</span><b>{{len .Findings}}</b><span class="mut">of {{len .Results}} probes</span></div>
<div class="kpi"><span class="mut">Money at risk (modelled)</span><b>{{money .ExposureINR}}</b></div>
<div class="kpi"><span class="mut">Requests spent</span><b>{{.Requests}}</b><span class="mut">budget {{.Budget}}</span></div>
</div>

<h2>Probe results</h2><div class="wrap"><table><tr><th>Probe</th><th>Check</th><th>Result</th><th>Notes</th><th>Req</th></tr>
{{range .Results}}<tr><td><code>{{.Probe}}</code></td><td>{{.Title}}</td>
<td>{{if .Finding}}<span class="sev {{.Finding.Severity}}">{{upper .Finding.Severity}}</span>{{else if .Error}}<span class="sev high">ERROR</span>{{else}}<span class="sev pass">PASS</span>{{end}}</td>
<td>{{if .Finding}}{{.Finding.Exposure}}{{else if .Error}}{{.Error}}{{else}}{{.Note}}{{end}}</td><td>{{.Requests}}</td></tr>{{end}}
</table></div>

{{if .Findings}}<h2>Control impact</h2><div class="wrap"><table><tr><th>Framework</th><th>Ref</th><th>Requirement</th><th>Broken by</th></tr>
{{range .ControlMatrix}}<tr><td>{{.Framework}}</td><td>{{.Ref}}</td><td>{{.Title}}</td><td>{{range .Findings}}<span class="tag">{{.}}</span>{{end}}</td></tr>{{end}}
</table></div>

<h2>Findings</h2>
{{range .Findings}}<div class="f"><h3><span class="sev {{.Severity}}">{{upper .Severity}}</span> {{.Title}}</h3>
<div class="mut"><code>{{.ID}}</code> · invariant <b>{{.Invariant}}</b> · {{.CWE}}</div>
<p>{{.Summary}}</p><p><b>Exposure:</b> {{.Exposure}}</p><p><b>Fix:</b> {{.Remediation}}</p>
<div>{{range .Violations}}<span class="tag">{{.Invariant}}: {{.Detail}}</span>{{end}}</div>
<details><summary>Evidence ({{len .Evidence}} exchanges)</summary>{{range .Evidence}}<pre>{{.Method}} {{.URL}}   [as {{.Identity}}]
{{.ReqBody}}

← HTTP {{.Status}} ({{.DurationMS}} ms)
{{.RespBody}}</pre>{{end}}</details></div>{{end}}{{end}}
<p class="mut" style="margin-top:32px">Control mappings are indicative and must be validated by the bank's compliance function. LedgerGuard used only designated test identities and accounts within the declared scope.</p>
</main></body></html>`))
