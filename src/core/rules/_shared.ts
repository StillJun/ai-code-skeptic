// src/core/rules/_shared.ts
import { Finding, Fix, Language, RuleContext, Severity } from "../types";
import { maskStringsAndComments } from "../helpers";

export const JS_LIKE: Language[] = ["javascript", "typescript"];
export const C_FAMILY: Language[] = ["c", "cpp"];
export const BRACE_LANGS: Language[] = [
  "javascript", "typescript", "php", "java", "csharp", "go", "rust", "c", "cpp",
];

export const isJsLike = (l: Language) => l === "javascript" || l === "typescript";
export const inList = (langs: Language[]) => (l: Language) => langs.includes(l);
export const always = () => true;

export function mk(
  ruleId: string,
  ruleTitle: string,
  severity: Severity,
  line: number,
  column: number,
  endColumn: number,
  message: string,
  suggestion?: string,
  fix?: Fix
): Finding {
  return { ruleId, ruleTitle, severity, line, column, endColumn, message, suggestion, fix };
}

/** Iterate over lines giving raw + masked (strings/comments blanked). */
export function eachCodeLine(
  ctx: RuleContext,
  cb: (raw: string, masked: string, lineNo: number) => void
) {
  for (let i = 0; i < ctx.lines.length; i++) {
    cb(ctx.lines[i], maskStringsAndComments(ctx.lines[i], ctx.language), i);
  }
}

/** Build a single-line replacement fix. */
export function replaceFix(
  title: string,
  line: number,
  column: number,
  endColumn: number,
  newText: string
): Fix {
  return { title, edits: [{ line, column, endLine: line, endColumn, newText }] };
}

/** Build a fix that deletes an entire line (including trailing newline). */
export function deleteLineFix(title: string, line: number, lineText: string): Fix {
  return { title, edits: [{ line, column: 0, endLine: line + 1, endColumn: 0, newText: "" }] };
}
