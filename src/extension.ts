// src/extension.ts
import * as vscode from "vscode";
import { analyze, computeTrust } from "./core/analyzer";
import { detectLanguage } from "./core/helpers";
import { Finding, Severity, TrustResult } from "./core/types";

const COLLECTION_NAME = "aiSkeptic";
let collection: vscode.DiagnosticCollection;
let statusItem: vscode.StatusBarItem;
let enabled = true;
const debounceTimers = new Map<string, NodeJS.Timeout>();
const lastResults = new Map<string, TrustResult>();
const findingIndex = new Map<string, Map<string, Finding>>();

const SUPPORTED = new Set([
  "javascript", "typescript", "javascriptreact", "typescriptreact",
  "python", "php", "java", "csharp", "go", "ruby", "rust", "c", "cpp",
]);

function sevToVsCode(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case "critical":
    case "high": return vscode.DiagnosticSeverity.Error;
    case "medium": return vscode.DiagnosticSeverity.Warning;
    case "low": return vscode.DiagnosticSeverity.Information;
    default: return vscode.DiagnosticSeverity.Hint;
  }
}

const SEV_EMOJI: Record<Severity, string> = {
  critical: "🛑", high: "🔴", medium: "🟠", low: "🟡", info: "🔵",
};

function getConfig() {
  const cfg = vscode.workspace.getConfiguration("aiSkeptic");
  return {
    enableOnType: cfg.get<boolean>("enableOnType", true),
    debounceMs: cfg.get<number>("debounceMs", 400),
    minSeverity: cfg.get<Severity>("minSeverity", "low"),
    disabledRules: cfg.get<string[]>("disabledRules", []),
  };
}

function keyFor(f: Finding): string {
  return `${f.line}:${f.column}:${f.ruleId}`;
}

function findingToDiagnostic(doc: vscode.TextDocument, f: Finding): vscode.Diagnostic {
  const safeLine = Math.min(f.line, doc.lineCount - 1);
  const lineLen = doc.lineAt(safeLine).text.length;
  const startCol = Math.max(0, Math.min(f.column, lineLen));
  const endCol = Math.max(startCol + 1, Math.min(f.endColumn, lineLen));
  const range = new vscode.Range(safeLine, startCol, safeLine, endCol);
  const message = f.suggestion ? `${f.message}\n💡 ${f.suggestion}` : f.message;
  const diag = new vscode.Diagnostic(range, message, sevToVsCode(f.severity));
  diag.source = "AI Skeptic";
  diag.code = f.ruleId;
  return diag;
}

function analyzeDocument(doc: vscode.TextDocument): TrustResult | null {
  if (!SUPPORTED.has(doc.languageId)) return null;
  const cfg = getConfig();
  const language = detectLanguage(doc.languageId, doc.fileName);
  const findings = analyze(doc.getText(), {
    language,
    disabledRules: cfg.disabledRules,
    minSeverity: cfg.minSeverity,
  });
  const result = computeTrust(findings);

  const uri = doc.uri.toString();
  lastResults.set(uri, result);
  const fmap = new Map<string, Finding>();
  for (const f of findings) fmap.set(keyFor(f), f);
  findingIndex.set(uri, fmap);

  collection.set(doc.uri, findings.map((f) => findingToDiagnostic(doc, f)));
  return result;
}

function clearDocument(doc: vscode.TextDocument) {
  const uri = doc.uri.toString();
  collection.delete(doc.uri);
  lastResults.delete(uri);
  findingIndex.delete(uri);
}

function updateStatusBar(result: TrustResult | null) {
  if (!result) { statusItem.hide(); return; }
  const icon =
    result.label === "Trusted" ? "$(shield)" :
    result.label === "Caution" ? "$(warning)" :
    result.label === "Questionable" ? "$(alert)" : "$(error)";
  statusItem.text = `${icon} Skeptic: ${result.score}/100`;
  statusItem.tooltip = new vscode.MarkdownString(
    `**AI Code Skeptic — ${result.label}**\n\n` +
    `🛑 critical: ${result.counts.critical} · 🔴 high: ${result.counts.high}\n\n` +
    `🟠 medium: ${result.counts.medium} · 🟡 low: ${result.counts.low}\n\n` +
    `${result.fixable} auto-fixable · click for full report`
  );
  statusItem.show();
}

function refresh(doc: vscode.TextDocument) {
  if (!enabled) return;
  const result = analyzeDocument(doc);
  if (vscode.window.activeTextEditor?.document.uri.toString() === doc.uri.toString()) {
    updateStatusBar(result);
  }
}

function scheduleRefresh(doc: vscode.TextDocument) {
  if (!enabled) return;
  const cfg = getConfig();
  if (!cfg.enableOnType) return;
  const key = doc.uri.toString();
  const prev = debounceTimers.get(key);
  if (prev) clearTimeout(prev);
  debounceTimers.set(key, setTimeout(() => {
    debounceTimers.delete(key);
    refresh(doc);
  }, cfg.debounceMs));
}

class SkepticCodeActions implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    doc: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const fmap = findingIndex.get(doc.uri.toString());
    if (!fmap) return actions;

    for (const diag of context.diagnostics) {
      if (diag.source !== "AI Skeptic") continue;
      const ruleId = String(diag.code);
      let found: Finding | undefined;
      for (const f of fmap.values()) {
        if (f.ruleId === ruleId && f.line === diag.range.start.line) { found = f; break; }
      }
      if (!found) continue;

      if (found.fix) {
        const action = new vscode.CodeAction(found.fix.title, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diag];
        const edit = new vscode.WorkspaceEdit();
        for (const e of found.fix.edits) {
          edit.replace(doc.uri, new vscode.Range(e.line, e.column, e.endLine, e.endColumn), e.newText);
        }
        action.edit = edit;
        actions.push(action);
      }

      const suppress = new vscode.CodeAction(`Ignore '${ruleId}' on this line`, vscode.CodeActionKind.QuickFix);
      suppress.diagnostics = [diag];
      const sEdit = new vscode.WorkspaceEdit();
      const line = doc.lineAt(found.line);
      const comment = commentTokenFor(doc.languageId);
      sEdit.insert(doc.uri, new vscode.Position(found.line, line.text.length),
        ` ${comment} ai-skeptic-disable-line ${ruleId}`);
      suppress.edit = sEdit;
      actions.push(suppress);
    }
    return actions;
  }
}

function commentTokenFor(langId: string): string {
  if (langId === "python" || langId === "ruby") return "#";
  return "//";
}

async function fixAll(doc: vscode.TextDocument) {
  const result = analyzeDocument(doc);
  if (!result) return;
  const fixables = result.findings.filter((f) => f.fix);
  if (fixables.length === 0) {
    vscode.window.showInformationMessage("AI Skeptic: no auto-fixable issues in this file.");
    return;
  }
  const edits = fixables
    .flatMap((f) => f.fix!.edits)
    .sort((a, b) => b.line - a.line || b.column - a.column);
  const wEdit = new vscode.WorkspaceEdit();
  for (const e of edits) {
    wEdit.replace(doc.uri, new vscode.Range(e.line, e.column, e.endLine, e.endColumn), e.newText);
  }
  await vscode.workspace.applyEdit(wEdit);
  vscode.window.showInformationMessage(`AI Skeptic: applied ${fixables.length} fix(es).`);
  refresh(doc);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function buildReportHtml(doc: vscode.TextDocument, result: TrustResult): string {
  const color =
    result.label === "Trusted" ? "#3fb950" :
    result.label === "Caution" ? "#d29922" :
    result.label === "Questionable" ? "#db6d28" : "#f85149";
  const rows = result.findings.map((f) => `<tr>
      <td>${SEV_EMOJI[f.severity]} ${f.severity}</td>
      <td><code>${escapeHtml(f.ruleId)}</code></td>
      <td>${f.line + 1}</td>
      <td>${escapeHtml(f.message)}${f.suggestion ? `<div class="hint">💡 ${escapeHtml(f.suggestion)}</div>` : ""}${f.fix ? `<div class="fixable">⚡ auto-fixable</div>` : ""}</td>
    </tr>`).join("");
  const fileName = doc.fileName.split(/[\\/]/).pop() ?? doc.fileName;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
  <style>
    body { font-family: "JetBrains Mono", Consolas, monospace; background:#0d1117; color:#c9d1d9; padding:20px; }
    h1 { color:#58a6ff; font-size:18px; }
    .score-box { display:flex; align-items:center; gap:20px; margin:18px 0; padding:18px;
      border:1px solid #30363d; border-radius:10px; background:#161b22; }
    .score { font-size:46px; font-weight:bold; color:${color}; }
    .label { font-size:20px; color:${color}; }
    .counts { color:#8b949e; font-size:13px; margin-top:4px; }
    table { width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; }
    th,td { text-align:left; padding:8px 10px; border-bottom:1px solid #21262d; vertical-align:top; }
    th { color:#58a6ff; }
    code { color:#7ee787; }
    .hint { color:#8b949e; margin-top:4px; font-style:italic; }
    .fixable { color:#d29922; margin-top:2px; font-size:12px; }
    .clean { color:#3fb950; font-size:15px; }
  </style></head><body>
  <h1>🕵️ AI Code Skeptic — report: ${escapeHtml(fileName)}</h1>
  <div class="score-box">
    <div class="score">${result.score}<span style="font-size:18px;color:#8b949e">/100</span></div>
    <div>
      <div class="label">${result.label}</div>
      <div class="counts">🛑 ${result.counts.critical} · 🔴 ${result.counts.high} · 🟠 ${result.counts.medium} · 🟡 ${result.counts.low} &nbsp;·&nbsp; ⚡ ${result.fixable} auto-fixable</div>
    </div>
  </div>
  ${result.findings.length === 0
      ? `<p class="clean">✅ No suspicious patterns found. Not a guarantee — still review by hand.</p>`
      : `<table><thead><tr><th>Severity</th><th>Rule</th><th>Line</th><th>Issue</th></tr></thead><tbody>${rows}</tbody></table>`}
  </body></html>`;
}

function showReport() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showInformationMessage("AI Skeptic: no active file."); return; }
  const doc = editor.document;
  if (!SUPPORTED.has(doc.languageId)) {
    vscode.window.showInformationMessage(`AI Skeptic: language '${doc.languageId}' is not supported yet.`);
    return;
  }
  const result = analyzeDocument(doc) ?? computeTrust([]);
  const panel = vscode.window.createWebviewPanel(
    "aiSkepticReport", "AI Skeptic — report", vscode.ViewColumn.Beside, { enableScripts: false }
  );
  panel.webview.html = buildReportHtml(doc, result);
}

export function activate(context: vscode.ExtensionContext) {
  collection = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);
  context.subscriptions.push(collection);

  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusItem.command = "aiSkeptic.showReport";
  context.subscriptions.push(statusItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("aiSkeptic.analyzeActive", () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) { refresh(ed.document); vscode.window.showInformationMessage("AI Skeptic: file analyzed."); }
    }),
    vscode.commands.registerCommand("aiSkeptic.showReport", showReport),
    vscode.commands.registerCommand("aiSkeptic.fixAll", () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) fixAll(ed.document);
    }),
    vscode.commands.registerCommand("aiSkeptic.toggle", () => {
      enabled = !enabled;
      if (!enabled) { collection.clear(); statusItem.hide(); }
      else if (vscode.window.activeTextEditor) refresh(vscode.window.activeTextEditor.document);
      vscode.window.showInformationMessage(`AI Skeptic: analysis ${enabled ? "enabled" : "disabled"}.`);
    })
  );

  const selectors = [...SUPPORTED].map((language) => ({ language, scheme: "file" }));
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(selectors, new SkepticCodeActions(), {
      providedCodeActionKinds: SkepticCodeActions.kinds,
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => refresh(doc)),
    vscode.workspace.onDidChangeTextDocument((e) => scheduleRefresh(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => clearDocument(doc)),
    vscode.window.onDidChangeActiveTextEditor((ed) => {
      if (ed) {
        const cached = lastResults.get(ed.document.uri.toString());
        if (cached) updateStatusBar(cached); else refresh(ed.document);
      } else statusItem.hide();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("aiSkeptic") && vscode.window.activeTextEditor)
        refresh(vscode.window.activeTextEditor.document);
    })
  );

  if (vscode.window.activeTextEditor) refresh(vscode.window.activeTextEditor.document);
}

export function deactivate() {
  collection?.dispose();
  statusItem?.dispose();
  for (const t of debounceTimers.values()) clearTimeout(t);
  debounceTimers.clear();
}
