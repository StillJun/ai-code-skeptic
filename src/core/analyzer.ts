// src/core/analyzer.ts
import { Finding, Language, RuleContext, Severity, SEVERITY_WEIGHT, severityRank, TrustResult } from "./types";
import { RULES, RULE_INDEX } from "./rules/index";
import { inlineDisabledFor, splitLines } from "./helpers";

export interface AnalyzeOptions {
  language: Language;
  disabledRules?: string[];
  minSeverity?: Severity;
}

export function analyze(text: string, opts: AnalyzeOptions): Finding[] {
  const lines = splitLines(text);
  const ctx: RuleContext = { text, lines, language: opts.language };
  const disabled = new Set(opts.disabledRules ?? []);
  const minRank = opts.minSeverity ? severityRank(opts.minSeverity) : -1;

  const findings: Finding[] = [];
  for (const rule of RULES) {
    if (disabled.has(rule.id)) continue;
    if (!rule.appliesTo(opts.language)) continue;
    let res: Finding[] = [];
    try {
      res = rule.check(ctx);
    } catch {
      res = []; // one broken rule must never crash the whole analysis
    }
    for (const f of res) {
      if (severityRank(f.severity) < minRank) continue;
      // honour inline disable comments
      const dis = inlineDisabledFor(lines, f.line);
      if (dis.all || dis.ids.has(f.ruleId)) continue;
      findings.push(f);
    }
  }

  findings.sort((a, b) =>
    a.line - b.line ||
    a.column - b.column ||
    severityRank(b.severity) - severityRank(a.severity)
  );
  return findings;
}

export function computeTrust(findings: Finding[]): TrustResult {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  let penalty = 0;
  let fixable = 0;
  for (const f of findings) {
    counts[f.severity]++;
    penalty += SEVERITY_WEIGHT[f.severity];
    if (f.fix) fixable++;
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));

  let label: TrustResult["label"];
  if (counts.critical > 0 || score < 40) label = "Do not trust";
  else if (score < 65) label = "Questionable";
  else if (score < 90) label = "Caution";
  else label = "Trusted";

  return { score, label, findings, counts, fixable };
}

export function analyzeWithTrust(text: string, opts: AnalyzeOptions): TrustResult {
  return computeTrust(analyze(text, opts));
}

export { RULES, RULE_INDEX };
