// src/core/rules/quality.ts
import { Finding, Rule } from "../types";
import { indentOf, maskStringsAndComments } from "../helpers";
import { always, deleteLineFix, eachCodeLine, isJsLike, mk, replaceFix } from "./_shared";

// Debug leftovers -----------------------------------------------------------
const debugLeftover: Rule = {
  id: "quality.debug-leftover",
  title: "Debug output left in",
  severity: "low",
  description: "Forgotten console.log / var_dump / printStackTrace etc.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      let re: RegExp | null = null;
      if (isJsLike(ctx.language)) re = /\bconsole\.(?:log|debug|info)\s*\(/;
      else if (ctx.language === "php") re = /\b(?:var_dump|print_r|var_export)\s*\(/;
      else if (ctx.language === "java") re = /\b(?:System\.out\.println|printStackTrace)\s*\(/;
      else if (ctx.language === "csharp") re = /\bConsole\.WriteLine\s*\(/;
      else if (ctx.language === "go") re = /\bfmt\.Print(?:ln|f)?\s*\(/;
      else if (ctx.language === "ruby") re = /\b(?:puts|p)\s+/;
      else if ((ctx.language === "c" || ctx.language === "cpp") && /\/\/\s*(?:debug|test)/i.test(raw)) re = /\bprintf\s*\(/;
      else if (ctx.language === "python" && /#\s*(?:debug|test|fixme)/i.test(raw)) re = /\bprint\s*\(/;
      if (!re) return;
      const m = masked.match(re);
      if (m && m.index !== undefined) {
        const onlyStmt = raw.trim().length > 0 && new RegExp(`^\\s*${re.source}`).test(masked);
        out.push(mk(debugLeftover.id, debugLeftover.title, "low", i, m.index, m.index + m[0].length,
          "Looks like leftover debug output.",
          "Remove before committing or use a proper logger.",
          onlyStmt ? deleteLineFix("Remove this debug line", i, raw) : undefined));
      }
    });
    return out;
  },
};

// Placeholder / unfinished code ---------------------------------------------
const placeholder: Rule = {
  id: "quality.placeholder",
  title: "Unfinished code",
  severity: "medium",
  description: "TODO / FIXME / 'your code here' markers.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const re = /\b(TODO|FIXME|XXX|HACK)\b|your code here|implement (?:this|me)|not implemented|\bplaceholder\b/i;
    for (let i = 0; i < ctx.lines.length; i++) {
      const m = ctx.lines[i].match(re);
      if (m && m.index !== undefined) {
        out.push(mk(placeholder.id, placeholder.title, "medium", i, m.index, m.index + m[0].length,
          "Marker of unfinished code. AI often leaves stubs instead of real logic.",
          "Implement the logic or remove the marker if it's stale."));
      }
    }
    return out;
  },
};

// Long function -------------------------------------------------------------
const longFunction: Rule = {
  id: "quality.long-function",
  title: "Function is too long",
  severity: "low",
  description: "Functions over 60 lines often hide logic errors.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const LIMIT = 60;
    const lines = ctx.lines;
    const headerRe =
      ctx.language === "python" ? /^\s*def\s+(\w+)/ :
      ctx.language === "ruby" ? /^\s*def\s+(\w+)/ :
      ctx.language === "go" ? /\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(/ :
      ctx.language === "php" ? /\bfunction\s+(\w+)\s*\(/ :
      /\bfunction\s+(\w+)\s*\(|\b(\w+)\s*=\s*\([^)]*\)\s*=>|\b(?:public|private|protected|static|\s)*\b(\w+)\s*\([^)]*\)\s*\{/;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(headerRe);
      if (!m) continue;
      const name = m[1] || m[2] || m[3] || "anonymous";
      if (ctx.language === "python" || ctx.language === "ruby") {
        const baseIndent = indentOf(lines[i]);
        let j = i + 1, last = i;
        const ender = ctx.language === "ruby" ? /^\s*end\s*$/ : null;
        while (j < lines.length) {
          if (lines[j].trim() === "") { j++; continue; }
          if (ender && ender.test(lines[j]) && indentOf(lines[j]) <= baseIndent) { last = j; break; }
          if (!ender && indentOf(lines[j]) <= baseIndent) break;
          last = j; j++;
        }
        const len = last - i + 1;
        if (len > LIMIT)
          out.push(mk(longFunction.id, longFunction.title, "low", i, 0, lines[i].length,
            `Function '${name}' is ~${len} lines. Long AI-written functions often hide logic errors.`,
            "Split it into smaller functions and add tests."));
      } else {
        let depth = 0, started = false, j = i, last = i;
        for (; j < lines.length; j++) {
          for (const ch of maskStringsAndComments(lines[j], ctx.language)) {
            if (ch === "{") { depth++; started = true; }
            else if (ch === "}") depth--;
          }
          last = j;
          if (started && depth <= 0) break;
        }
        const len = last - i + 1;
        if (started && len > LIMIT)
          out.push(mk(longFunction.id, longFunction.title, "low", i, 0, lines[i].length,
            `Function '${name}' is ~${len} lines.`,
            "Split it into smaller functions and add tests."));
      }
    }
    return out;
  },
};

// TODO done — magic numbers is noisy; keep off by default. Instead: empty block.
const emptyBlock: Rule = {
  id: "quality.empty-block",
  title: "Empty block",
  severity: "low",
  description: "Empty if/else/loop body — likely forgotten logic.",
  appliesTo: (l) => !["python", "ruby"].includes(l),
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/\b(if|else|for|while)\b\s*(\([^)]*\))?\s*\{\s*\}/);
      if (m && m.index !== undefined) {
        out.push(mk(emptyBlock.id, emptyBlock.title, "low", i, m.index, m.index + m[0].length,
          `Empty ${m[1]} body — logic may have been left out.`,
          "Fill in the body or remove the empty construct."));
      }
    });
    return out;
  },
};

export const qualityRules: Rule[] = [debugLeftover, placeholder, longFunction, emptyBlock];
