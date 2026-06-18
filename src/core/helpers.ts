// src/core/helpers.ts
import { Language } from "./types";

const EXT_MAP: Array<[RegExp, Language]> = [
  [/\.tsx?$/i, "typescript"],
  [/\.(jsx?|mjs|cjs)$/i, "javascript"],
  [/\.py$/i, "python"],
  [/\.php$/i, "php"],
  [/\.java$/i, "java"],
  [/\.cs$/i, "csharp"],
  [/\.go$/i, "go"],
  [/\.rb$/i, "ruby"],
  [/\.rs$/i, "rust"],
  [/\.(cpp|cc|cxx|hpp|hh)$/i, "cpp"],
  [/\.(c|h)$/i, "c"],
];

const LANG_ID_MAP: Record<string, Language> = {
  javascript: "javascript",
  javascriptreact: "javascript",
  typescript: "typescript",
  typescriptreact: "typescript",
  python: "python",
  php: "php",
  java: "java",
  csharp: "csharp",
  go: "go",
  ruby: "ruby",
  rust: "rust",
  c: "c",
  cpp: "cpp",
  "objective-c": "c",
};

export function detectLanguage(langId: string, fileName = ""): Language {
  const id = (langId || "").toLowerCase();
  if (LANG_ID_MAP[id]) return LANG_ID_MAP[id];
  for (const [re, lang] of EXT_MAP) if (re.test(fileName)) return lang;
  return "unknown";
}

export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/);
}

/** Languages that use '#' for line comments. */
const HASH_COMMENT: Language[] = ["python", "ruby"];
/** Languages that have C-style /* *​/ block comments. */
const BLOCK_COMMENT: Language[] = [
  "javascript", "typescript", "php", "java", "csharp", "go", "rust", "c", "cpp",
];

export function lineCommentTokens(lang: Language): string[] {
  if (lang === "python" || lang === "ruby") return ["#"];
  if (lang === "php") return ["//", "#"];
  return ["//"];
}

export function isCommentLine(line: string, lang: Language): boolean {
  const t = line.trim();
  if (t === "") return false;
  if (HASH_COMMENT.includes(lang)) return t.startsWith("#");
  if (lang === "php") return t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*");
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");
}

/**
 * Replaces the *contents* of string literals, line comments and same-line block
 * comments with spaces (keeping length so columns stay valid). This prevents
 * regex rules from firing on text inside strings/comments.
 */
export function maskStringsAndComments(line: string, lang: Language): string {
  const chars = line.split("");
  const n = chars.length;
  let i = 0;
  let inStr: '"' | "'" | "`" | null = null;
  let escaped = false;
  const lineTokens = lineCommentTokens(lang);
  const hasBlock = BLOCK_COMMENT.includes(lang);

  while (i < n) {
    const c = chars[i];

    if (inStr) {
      if (escaped) escaped = false;
      else if (c === "\\" && lang !== "go") escaped = true; // Go raw strings rarely escape; keep simple
      else if (c === inStr) { inStr = null; chars[i] = " "; i++; continue; }
      chars[i] = " ";
      i++;
      continue;
    }

    if (c === '"' || c === "'" || c === "`") { inStr = c as any; i++; continue; }

    // line comment?
    let matched = false;
    for (const tok of lineTokens) {
      if (line.startsWith(tok, i)) {
        for (let j = i; j < n; j++) chars[j] = " ";
        matched = true;
        break;
      }
    }
    if (matched) break;

    // same-line block comment /* ... */
    if (hasBlock && line.startsWith("/*", i)) {
      const close = line.indexOf("*/", i + 2);
      const end = close === -1 ? n : close + 2;
      for (let j = i; j < end; j++) chars[j] = " ";
      i = end;
      continue;
    }

    i++;
  }
  return chars.join("");
}

export function findAll(line: string, re: RegExp): Array<{ start: number; end: number; match: RegExpExecArray }> {
  const out: Array<{ start: number; end: number; match: RegExpExecArray }> = [];
  const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = r.exec(line)) !== null) {
    out.push({ start: m.index, end: m.index + m[0].length, match: m });
    if (m.index === r.lastIndex) r.lastIndex++;
  }
  return out;
}

export function indentOf(line: string): number {
  const m = line.match(/^[ \t]*/);
  return m ? m[0].length : 0;
}

const DISABLE_LINE = /(?:\/\/|#)\s*ai-skeptic-disable-line\b(.*)$/;
const DISABLE_NEXT = /(?:\/\/|#)\s*ai-skeptic-disable-next-line\b(.*)$/;

/** Returns the set of ruleIds disabled for `lineNo` via inline comments (empty Set = none, but "ALL" sentinel = all). */
export function inlineDisabledFor(lines: string[], lineNo: number): { all: boolean; ids: Set<string> } {
  const ids = new Set<string>();
  let all = false;
  const check = (text: string | undefined) => {
    if (text === undefined) return;
    const onLine = text.match(DISABLE_LINE);
    if (onLine) {
      const rest = onLine[1].trim();
      if (rest === "") all = true;
      else rest.split(/[\s,]+/).filter(Boolean).forEach((id) => ids.add(id));
    }
  };
  // disable-line on the same line
  check(lines[lineNo]);
  // disable-next-line on the previous line
  const prev = lines[lineNo - 1];
  if (prev) {
    const m = prev.match(DISABLE_NEXT);
    if (m) {
      const rest = m[1].trim();
      if (rest === "") all = true;
      else rest.split(/[\s,]+/).filter(Boolean).forEach((id) => ids.add(id));
    }
  }
  return { all, ids };
}
