// src/core/rules/errors.ts
import { Finding, Rule } from "../types";
import { maskStringsAndComments } from "../helpers";
import { always, eachCodeLine, isJsLike, mk, replaceFix } from "./_shared";

// Silent / swallowed errors -------------------------------------------------
const silentCatch: Rule = {
  id: "errors.silent-catch",
  title: "Swallowed error",
  severity: "high",
  description: "Empty catch / except: pass hides failures.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const lines = ctx.lines;
    for (let i = 0; i < lines.length; i++) {
      const masked = maskStringsAndComments(lines[i], ctx.language);

      if (ctx.language === "python") {
        if (/\bexcept\b[^:]*:\s*$/.test(masked)) {
          let j = i + 1;
          while (j < lines.length && lines[j].trim() === "") j++;
          if (j < lines.length && /^\s*pass\s*$/.test(lines[j])) {
            const col = Math.max(0, lines[i].indexOf("except"));
            out.push(mk(silentCatch.id, silentCatch.title, "high", i, col, col + 6,
              "except: pass swallows the error silently.",
              "Log the exception (logging.exception) or re-raise it."));
          }
        } else if (/\bexcept\b[^:]*:\s*pass\s*$/.test(masked)) {
          const col = Math.max(0, lines[i].indexOf("except"));
          out.push(mk(silentCatch.id, silentCatch.title, "high", i, col, col + 6,
            "except: pass swallows the error silently.",
            "Log or re-raise the exception."));
        }
      } else if (ctx.language === "ruby") {
        if (/\brescue\b[^=]*$/.test(masked)) {
          let j = i + 1;
          while (j < lines.length && lines[j].trim() === "") j++;
          if (j < lines.length && /^\s*end\s*$/.test(lines[j])) {
            const col = Math.max(0, lines[i].indexOf("rescue"));
            out.push(mk(silentCatch.id, silentCatch.title, "high", i, col, col + 6,
              "Empty rescue block swallows the error.",
              "Handle or log the exception inside rescue."));
          }
        }
      } else {
        // brace languages: catch (...) {}  or  catch {}
        const m = masked.match(/\bcatch\b\s*(\([^)]*\))?\s*\{\s*\}/);
        if (m && m.index !== undefined) {
          let fix;
          if (isJsLike(ctx.language)) {
            const varName = (m[1] || "(e)").replace(/[()]/g, "").trim() || "e";
            fix = replaceFix("Log the error", i, m.index, m.index + m[0].length,
              `catch (${varName}) { console.error(${varName}); }`);
          }
          out.push(mk(silentCatch.id, silentCatch.title, "high", i, m.index, m.index + m[0].length,
            "Empty catch block swallows the error silently.",
            "Log the error or handle it meaningfully; never leave the block empty.", fix));
        }
      }
    }
    return out;
  },
};

// Overly broad catch --------------------------------------------------------
const broadCatch: Rule = {
  id: "errors.broad-catch",
  title: "Overly broad catch",
  severity: "medium",
  description: "Catching the base exception type hides unexpected failures.",
  appliesTo: (l) => ["python", "php", "java", "csharp", "ruby"].includes(l),
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      let m: RegExpMatchArray | null = null;
      if (ctx.language === "python") m = masked.match(/\bexcept\s*:/) || masked.match(/\bexcept\s+(?:BaseException|Exception)\s*[:,]/);
      else if (ctx.language === "php") m = masked.match(/\bcatch\s*\(\s*\\?(?:Throwable|Exception)\b/);
      else if (ctx.language === "java") m = masked.match(/\bcatch\s*\(\s*(?:Exception|Throwable)\b/);
      else if (ctx.language === "csharp") m = masked.match(/\bcatch\s*\(\s*(?:Exception|System\.Exception)\b/) || masked.match(/\bcatch\s*\{/);
      else if (ctx.language === "ruby") m = masked.match(/\brescue\s+(?:Exception|StandardError)\b/);
      if (m && m.index !== undefined) {
        out.push(mk(broadCatch.id, broadCatch.title, "medium", i, m.index, m.index + m[0].length,
          "Catching the broadest exception type masks bugs you didn't expect.",
          "Catch the specific exception types you can actually handle."));
      }
    });
    return out;
  },
};

// then() without catch ------------------------------------------------------
const unhandledRejection: Rule = {
  id: "js.unhandled-rejection",
  title: ".then without .catch",
  severity: "low",
  description: "Promise chain with no rejection handler.",
  appliesTo: isJsLike,
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const idx = masked.indexOf(".then");
      if (idx !== -1 && /\.then\s*\(/.test(masked) && !/\.catch\s*\(/.test(masked) && !/\bawait\b/.test(masked)) {
        out.push(mk(unhandledRejection.id, unhandledRejection.title, "low", i, idx, idx + 5,
          ".then without .catch leaves rejections unhandled.",
          "Add .catch() or switch to try/await."));
      }
    });
    return out;
  },
};

// floating promise ----------------------------------------------------------
const floatingPromise: Rule = {
  id: "js.floating-promise",
  title: "Promise not awaited",
  severity: "medium",
  description: "Async call whose result/errors are dropped.",
  appliesTo: isJsLike,
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/^\s*(fetch|axios(?:\.\w+)?)\s*\(/);
      if (m && m.index !== undefined && !/\b(await|return)\b/.test(masked) && !/=\s*(fetch|axios)/.test(masked)) {
        const idx = masked.indexOf(m[1]);
        out.push(mk(floatingPromise.id, floatingPromise.title, "medium", i, idx, idx + m[1].length,
          "Async call without await/then — its result and errors are lost.",
          "Add await (inside an async function) or chain .then().catch()."));
      }
    });
    return out;
  },
};

// Go: ignored error ---------------------------------------------------------
const goIgnoredError: Rule = {
  id: "go.ignored-error",
  title: "Ignored error",
  severity: "medium",
  description: "Error assigned to _ is silently discarded.",
  appliesTo: (l) => l === "go",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/,\s*_\s*:?=\s*\w/);
      if (m && m.index !== undefined && /\berr\b|\bError\b/.test(raw) === false && /\(/.test(masked)) {
        // heuristic: "x, _ := f()" where the discarded slot is likely an error
        out.push(mk(goIgnoredError.id, goIgnoredError.title, "medium", i, m.index, m.index + m[0].length,
          "A return value (often an error) is discarded with _.",
          "Check the error explicitly: if err != nil { ... }."));
      }
    });
    return out;
  },
};

export const errorRules: Rule[] = [
  silentCatch, broadCatch, unhandledRejection, floatingPromise, goIgnoredError,
];
