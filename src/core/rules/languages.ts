// src/core/rules/languages.ts
import { Finding, Rule } from "../types";
import { findAll } from "../helpers";
import { eachCodeLine, isJsLike, mk, replaceFix } from "./_shared";

// JS/TS: == / != ------------------------------------------------------------
const looseEquality: Rule = {
  id: "js.loose-equality",
  title: "Loose equality ==",
  severity: "low",
  description: "== / != trigger type coercion; prefer === / !==.",
  appliesTo: isJsLike,
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const re = /[^=!<>]([=!])=(?!=)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(masked)) !== null) {
        const opStart = m.index + 1;
        out.push(mk(looseEquality.id, looseEquality.title, "low", i, opStart, opStart + 2,
          `Loose '${m[1]}=' performs hidden type coercion.`,
          `Use strict '${m[1]}=='.`,
          replaceFix(`Replace with ${m[1]}==`, i, opStart, opStart + 2, `${m[1]}==`)));
      }
    });
    return out;
  },
};

// JS/TS: var ----------------------------------------------------------------
const varUsage: Rule = {
  id: "js.var-usage",
  title: "Use of var",
  severity: "low",
  description: "var is function-scoped and hoisted; prefer let/const.",
  appliesTo: isJsLike,
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      for (const hit of findAll(masked, /\bvar\s+(?=[A-Za-z_$])/g)) {
        out.push(mk(varUsage.id, varUsage.title, "low", i, hit.start, hit.start + 3,
          "var is function-scoped and hoisted — a common source of subtle bugs.",
          "Use const (or let if reassigned).",
          replaceFix("Replace var with let", i, hit.start, hit.start + 3, "let")));
      }
    });
    return out;
  },
};

// Python: mutable default ---------------------------------------------------
const mutableDefault: Rule = {
  id: "python.mutable-default",
  title: "Mutable default argument",
  severity: "medium",
  description: "Default [] / {} is shared across calls.",
  appliesTo: (l) => l === "python",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/\bdef\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|\bset\(\)|\bdict\(\)|\blist\(\))/);
      if (m && m.index !== undefined) {
        const litIdx = masked.indexOf(m[1], m.index);
        out.push(mk(mutableDefault.id, mutableDefault.title, "medium", i, m.index, m.index + m[0].length,
          "A mutable default ([]/{}) persists between calls — a classic Python bug.",
          "Default to None and create the object inside the function.",
          replaceFix("Replace default with None", i, litIdx, litIdx + m[1].length, "None")));
      }
    });
    return out;
  },
};

// Python: assert used for validation ----------------------------------------
const assertValidation: Rule = {
  id: "python.assert-validation",
  title: "assert used for validation",
  severity: "low",
  description: "assert is stripped with python -O; not for runtime checks.",
  appliesTo: (l) => l === "python",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/^\s*assert\s+\w/);
      if (m && m.index !== undefined && /\b(request|input|user|arg|param|token|auth|perm)\b/i.test(raw)) {
        const idx = masked.indexOf("assert");
        out.push(mk(assertValidation.id, assertValidation.title, "low", i, idx, idx + 6,
          "assert is removed when Python runs with -O, so it must not guard real validation.",
          "Raise an explicit exception (ValueError / PermissionError) instead."));
      }
    });
    return out;
  },
};

// Java: == on strings -------------------------------------------------------
const javaStringEq: Rule = {
  id: "java.string-equality",
  title: "== on String",
  severity: "medium",
  description: "== compares references, not String contents.",
  appliesTo: (l) => l === "java",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      // compare against a string literal: x == "..."  (literal was masked but quotes remain)
      const m = masked.match(/[A-Za-z_]\w*\s*[!=]=\s*"/) || masked.match(/"\s*[!=]=\s*[A-Za-z_]\w*/);
      if (m && m.index !== undefined) {
        out.push(mk(javaStringEq.id, javaStringEq.title, "medium", i, m.index, m.index + m[0].length,
          "== on Strings compares object identity, not the text.",
          "Use .equals() (or Objects.equals(a, b) for null-safety)."));
      }
    });
    return out;
  },
};

// Rust: unwrap / expect -----------------------------------------------------
const rustUnwrap: Rule = {
  id: "rust.unwrap",
  title: "unwrap()/expect() may panic",
  severity: "low",
  description: "unwrap/expect panic on None/Err.",
  appliesTo: (l) => l === "rust",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      for (const hit of findAll(masked, /\.(unwrap|expect)\s*\(/g)) {
        out.push(mk(rustUnwrap.id, rustUnwrap.title, "low", i, hit.start, hit.end,
          `.${hit.match[1]}() panics on None/Err and crashes the thread.`,
          "Handle the error with match / if let / the ? operator."));
      }
    });
    return out;
  },
};

// Rust: unsafe block --------------------------------------------------------
const rustUnsafe: Rule = {
  id: "rust.unsafe-block",
  title: "unsafe block",
  severity: "medium",
  description: "unsafe disables Rust's safety guarantees.",
  appliesTo: (l) => l === "rust",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/\bunsafe\s*\{/);
      if (m && m.index !== undefined) {
        out.push(mk(rustUnsafe.id, rustUnsafe.title, "medium", i, m.index, m.index + m[0].length,
          "unsafe turns off the borrow checker's guarantees — review carefully.",
          "Confirm the invariants hold and document why this block is sound."));
      }
    });
    return out;
  },
};

// PHP: loose equality -------------------------------------------------------
const phpLooseEq: Rule = {
  id: "php.loose-equality",
  title: "Loose equality ==",
  severity: "low",
  description: "PHP == has surprising coercion rules.",
  appliesTo: (l) => l === "php",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const re = /[^=!<>]([=!])=(?!=)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(masked)) !== null) {
        const opStart = m.index + 1;
        out.push(mk(phpLooseEq.id, phpLooseEq.title, "low", i, opStart, opStart + 2,
          `PHP '${m[1]}=' uses loose comparison with surprising coercion (e.g. "0" == false).`,
          `Use strict '${m[1]}=='.`,
          replaceFix(`Replace with ${m[1]}==`, i, opStart, opStart + 2, `${m[1]}==`)));
      }
    });
    return out;
  },
};

export const languageRules: Rule[] = [
  looseEquality, varUsage, mutableDefault, assertValidation,
  javaStringEq, rustUnwrap, rustUnsafe, phpLooseEq,
];
