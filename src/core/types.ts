// src/core/types.ts
// Pure core types. NO imports from 'vscode' so the engine is testable in plain Node.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Language =
  | "javascript"
  | "typescript"
  | "python"
  | "php"
  | "java"
  | "csharp"
  | "go"
  | "ruby"
  | "rust"
  | "c"
  | "cpp"
  | "unknown";

/** A single text edit used to auto-fix a finding. Positions are 0-based. */
export interface FixEdit {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  newText: string;
}

export interface Fix {
  title: string;
  edits: FixEdit[];
}

export interface Finding {
  ruleId: string;
  ruleTitle: string;
  message: string;
  severity: Severity;
  /** 0-based line */
  line: number;
  /** 0-based start column */
  column: number;
  /** exclusive end column */
  endColumn: number;
  /** how-to-fix hint shown to the user */
  suggestion?: string;
  /** optional automatic fix (Quick Fix) */
  fix?: Fix;
}

export interface RuleContext {
  text: string;
  lines: string[];
  language: Language;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** short human description for docs / report */
  description: string;
  appliesTo: (lang: Language) => boolean;
  check: (ctx: RuleContext) => Finding[];
}

export interface TrustResult {
  /** 0..100 */
  score: number;
  label: "Trusted" | "Caution" | "Questionable" | "Do not trust";
  findings: Finding[];
  counts: Record<Severity, number>;
  /** number of findings that ship an automatic fix */
  fixable: number;
}

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 1,
  low: 2,
  medium: 4,
  high: 8,
  critical: 16,
};

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}
