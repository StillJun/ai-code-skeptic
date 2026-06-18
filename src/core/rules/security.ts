// src/core/rules/security.ts
import { Finding, Rule } from "../types";
import { findAll } from "../helpers";
import { always, eachCodeLine, isJsLike, mk, replaceFix } from "./_shared";

// 1. Hardcoded secrets ------------------------------------------------------
const hardcodedSecret: Rule = {
  id: "secrets.hardcoded",
  title: "Hardcoded secret",
  severity: "critical",
  description: "API keys, tokens, passwords or private keys embedded directly in source.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const patterns: Array<{ re: RegExp; what: string }> = [
      { re: /\b(?:api[_-]?key|apikey|secret|token|passwd|password|access[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['"][^'"]{6,}['"]/i, what: "credentials" },
      { re: /\bAKIA[0-9A-Z]{16}\b/, what: "an AWS access key" },
      { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, what: "a GitHub token" },
      { re: /\bsk-[A-Za-z0-9]{20,}\b/, what: "a secret API key (sk-...)" },
      { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, what: "a Slack token" },
      { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, what: "a private key" },
    ];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      for (const p of patterns) {
        for (const hit of findAll(raw, p.re)) {
          if (/(your|example|placeholder|changeme|dummy|xxxx|<[^>]*>|\.\.\.|test[_-]?key|sample)/i.test(hit.match[0])) continue;
          out.push(mk(hardcodedSecret.id, hardcodedSecret.title, "critical", i, hit.start, hit.end,
            `Looks like ${p.what} hardcoded in source. AI assistants frequently paste real keys inline.`,
            "Move it to an environment variable / secrets manager and add the file to .gitignore."));
        }
      }
    }
    return out;
  },
};

// 2. SQL injection ----------------------------------------------------------
const sqlInjection: Rule = {
  id: "security.sql-injection",
  title: "Possible SQL injection",
  severity: "critical",
  description: "SQL query built by concatenating or interpolating variables.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const kw = /\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b/i;
    const tests = [
      /['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*['"]\s*\.\s*\$?\w/i,     // PHP "." concat
      /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^`]*\$\{[^}]+\}/i,                 // JS template
      /['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*['"]\s*\+\s*\w/i,         // + concat
      /(?:execute|query)\s*\(\s*f['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*\{[^}]+\}/i, // py f-string
      /['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^'"]*['"]\s*%\s*\(/i,          // py % format
    ];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (!kw.test(raw)) continue;
      for (const re of tests) {
        const m = raw.match(re);
        if (m && m.index !== undefined) {
          out.push(mk(sqlInjection.id, sqlInjection.title, "critical", i, m.index, m.index + m[0].length,
            "SQL query is assembled from a variable — classic injection vector.",
            "Use parameterized queries / prepared statements with bound placeholders (?, :name)."));
          break;
        }
      }
    }
    return out;
  },
};

// 3. Command injection ------------------------------------------------------
const commandInjection: Rule = {
  id: "security.command-injection",
  title: "Possible command injection",
  severity: "critical",
  description: "Shell command built from variables / user input.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      let re: RegExp | null = null;
      switch (ctx.language) {
        case "python": re = /\b(?:os\.system|subprocess\.(?:call|run|Popen))\s*\([^)]*\+|shell\s*=\s*True/; break;
        case "php": re = /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$/; break;
        case "ruby": re = /\b(?:system|exec|`[^`]*#\{)|%x\{/; break;
        case "java": re = /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/; break;
        case "csharp": re = /Process\.Start\s*\([^)]*\+/; break;
        case "go": re = /exec\.Command\s*\([^)]*\+/; break;
        case "c": case "cpp": re = /\b(?:system|popen)\s*\([^)]*(?:\+|,)/; break;
        default:
          if (isJsLike(ctx.language)) re = /\b(?:exec|execSync)\s*\(\s*[`'"][^`'"]*\$\{|\bexec(?:Sync)?\s*\([^)]*\+/;
      }
      if (!re) continue;
      const m = raw.match(re);
      if (m && m.index !== undefined) {
        out.push(mk(commandInjection.id, commandInjection.title, "critical", i, m.index, m.index + m[0].length,
          "A shell command is built from a variable / input — remote code execution risk.",
          "Pass arguments as an array (no shell), avoid shell=True, and validate input strictly."));
      }
    }
    return out;
  },
};

// 4. XSS --------------------------------------------------------------------
const xss: Rule = {
  id: "security.xss",
  title: "Possible XSS",
  severity: "high",
  description: "Unsanitized data written into the DOM or echoed to a page.",
  appliesTo: (l) => isJsLike(l) || l === "php",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      if (isJsLike(ctx.language)) {
        const m = masked.match(/(\w[\w.$\[\]]*)\.innerHTML\s*=\s*[^;]*[\w)\]]/);
        if (m && m.index !== undefined && !/=\s*['"]?\s*$/.test(masked)) {
          const idx = masked.indexOf(".innerHTML", m.index);
          out.push(mk(xss.id, xss.title, "high", i, idx, idx + ".innerHTML".length,
            "Assigning unvalidated data to innerHTML enables XSS.",
            "Use textContent, or sanitize HTML (DOMPurify) before insertion.",
            replaceFix("Replace .innerHTML with .textContent", i, idx, idx + ".innerHTML".length, ".textContent")));
        }
        const d = masked.indexOf("dangerouslySetInnerHTML");
        if (d !== -1) {
          out.push(mk(xss.id, xss.title, "high", i, d, d + "dangerouslySetInnerHTML".length,
            "dangerouslySetInnerHTML without sanitization is an XSS sink.",
            "Sanitize the HTML (DOMPurify) before rendering."));
        }
      }
      if (ctx.language === "php") {
        const m = raw.match(/echo\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/);
        if (m && m.index !== undefined) {
          out.push(mk(xss.id, xss.title, "high", i, m.index, m.index + m[0].length,
            "Echoing user input without escaping enables XSS.",
            "Wrap output in htmlspecialchars($x, ENT_QUOTES, 'UTF-8')."));
        }
      }
    });
    return out;
  },
};

// 5. eval / dynamic exec ----------------------------------------------------
const dangerousEval: Rule = {
  id: "security.eval",
  title: "Dangerous eval/exec",
  severity: "high",
  description: "Dynamic execution of code from a string.",
  appliesTo: (l) => ["python", "php", "ruby", "javascript", "typescript"].includes(l),
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      let re: RegExp;
      if (ctx.language === "python") re = /\b(?:eval|exec)\s*\(/;
      else if (ctx.language === "php") re = /\b(?:eval|assert|create_function)\s*\(/;
      else if (ctx.language === "ruby") re = /\b(?:eval|instance_eval|class_eval)\s*[\s(]/;
      else re = /\beval\s*\(/;
      for (const hit of findAll(masked, re)) {
        out.push(mk(dangerousEval.id, dangerousEval.title, "high", i, hit.start, hit.end,
          "Dynamic code execution (eval/exec) is a frequent RCE source.",
          "Replace with explicit parsing or a dispatch table; never execute strings."));
      }
    });
    return out;
  },
};

// 6. Disabled TLS verification ---------------------------------------------
const sslDisabled: Rule = {
  id: "security.ssl-disabled",
  title: "TLS verification disabled",
  severity: "high",
  description: "Certificate verification turned off, enabling MITM.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    const fixers: Array<{ re: RegExp; fix?: (m: RegExpMatchArray, i: number) => any }> = [
      { re: /rejectUnauthorized\s*:\s*false/i },
      { re: /verify\s*=\s*False/ },
      { re: /CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/i },
      { re: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i },
      { re: /InsecureSkipVerify\s*:\s*true/i },
      { re: /ServerCertificateValidationCallback\s*=\s*[^;]*=>\s*true/i },
    ];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      for (const f of fixers) {
        const m = raw.match(f.re);
        if (m && m.index !== undefined) {
          let fix;
          if (/rejectUnauthorized\s*:\s*false/i.test(m[0]))
            fix = replaceFix("Set rejectUnauthorized: true", i, m.index, m.index + m[0].length, "rejectUnauthorized: true");
          else if (/verify\s*=\s*False/.test(m[0]))
            fix = replaceFix("Set verify=True", i, m.index, m.index + m[0].length, "verify=True");
          out.push(mk(sslDisabled.id, sslDisabled.title, "high", i, m.index, m.index + m[0].length,
            "TLS certificate verification is disabled — opens MITM attacks.",
            "Never disable verification. For self-signed certs, trust the CA instead.", fix));
        }
      }
    }
    return out;
  },
};

// 7. Weak randomness in security context ------------------------------------
const weakRandom: Rule = {
  id: "security.weak-random",
  title: "Insecure random generator",
  severity: "medium",
  description: "Non-cryptographic RNG used for security-sensitive values.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      if (!/\b(token|password|secret|otp|salt|nonce|session|csrf|api[_-]?key|reset|auth)\b/i.test(raw)) continue;
      let re: RegExp | null = null;
      if (isJsLike(ctx.language)) re = /Math\.random\s*\(/;
      else if (ctx.language === "python") re = /\brandom\.(?:random|randint|choice|randrange)\s*\(/;
      else if (ctx.language === "php") re = /\b(?:rand|mt_rand)\s*\(/;
      else if (ctx.language === "java") re = /new\s+Random\s*\(/;
      else if (ctx.language === "csharp") re = /new\s+Random\s*\(/;
      else if (ctx.language === "go") re = /\brand\.(?:Intn|Int|Float64)\s*\(/;
      else if (ctx.language === "ruby") re = /\brand\s*\(/;
      if (!re) continue;
      const m = raw.match(re);
      if (m && m.index !== undefined) {
        out.push(mk(weakRandom.id, weakRandom.title, "medium", i, m.index, m.index + m[0].length,
          "A predictable PRNG is used in a security context.",
          "Use a CSPRNG: crypto.randomBytes / secrets / random_bytes / SecureRandom / crypto/rand."));
      }
    }
    return out;
  },
};

// 8. Weak hash for security -------------------------------------------------
const weakHash: Rule = {
  id: "security.weak-hash",
  title: "Weak hash algorithm",
  severity: "medium",
  description: "MD5/SHA1 used where a strong hash is required.",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      const raw = ctx.lines[i];
      const re = /\b(?:md5|sha1)\b|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1)['"]|MD5\.Create|SHA1\.Create|hashlib\.(?:md5|sha1)/i;
      const m = raw.match(re);
      if (m && m.index !== undefined) {
        const secCtx = /\b(password|passwd|secret|token|hash|sign|integrity|digest)\b/i.test(raw);
        out.push(mk(weakHash.id, weakHash.title, secCtx ? "high" : "medium", i, m.index, m.index + m[0].length,
          "MD5/SHA-1 are broken for security use (collisions, fast to brute-force).",
          "Use SHA-256+ for integrity, and bcrypt/argon2/scrypt for passwords."));
      }
    }
    return out;
  },
};

// 9. Insecure deserialization ----------------------------------------------
const insecureDeser: Rule = {
  id: "security.insecure-deserialization",
  title: "Insecure deserialization",
  severity: "high",
  description: "Deserializing untrusted data can lead to RCE.",
  appliesTo: (l) => ["python", "php", "ruby", "java"].includes(l),
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      let re: RegExp | null = null;
      if (ctx.language === "python") re = /\b(?:pickle\.loads?|yaml\.load(?!_safe|s_safe)|marshal\.loads?)\s*\(/;
      else if (ctx.language === "php") re = /\bunserialize\s*\(/;
      else if (ctx.language === "ruby") re = /\b(?:Marshal\.load|YAML\.load)\s*\(/;
      else if (ctx.language === "java") re = /\bObjectInputStream\b|readObject\s*\(/;
      if (!re) return;
      const m = masked.match(re);
      if (m && m.index !== undefined) {
        // yaml.load with SafeLoader is fine
        if (ctx.language === "python" && /yaml\.load\b/.test(m[0]) && /SafeLoader|Loader\s*=\s*yaml\.Safe/.test(raw)) return;
        out.push(mk(insecureDeser.id, insecureDeser.title, "high", i, m.index, m.index + m[0].length,
          "Deserializing untrusted data may execute arbitrary code.",
          "Use safe formats (JSON) or safe loaders (yaml.safe_load); never unpickle untrusted input."));
      }
    });
    return out;
  },
};

// 10. Path traversal --------------------------------------------------------
const pathTraversal: Rule = {
  id: "security.path-traversal",
  title: "Possible path traversal",
  severity: "medium",
  description: "File path built from input without normalization.",
  appliesTo: (l) => ["python", "php", "javascript", "typescript", "java"].includes(l),
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      let re: RegExp | null = null;
      if (ctx.language === "python") re = /\bopen\s*\([^)]*(?:\+|\bos\.path\.join\([^)]*request|input\(|argv)/;
      else if (ctx.language === "php") re = /\b(?:fopen|file_get_contents|include|require)\s*\([^)]*\$_(?:GET|POST|REQUEST)/;
      else if (isJsLike(ctx.language)) re = /\b(?:readFile(?:Sync)?|createReadStream)\s*\([^)]*\+\s*req\./;
      else if (ctx.language === "java") re = /new\s+File\s*\([^)]*\+\s*request/;
      if (!re) return;
      const m = masked.match(re);
      if (m && m.index !== undefined) {
        out.push(mk(pathTraversal.id, pathTraversal.title, "medium", i, m.index, m.index + m[0].length,
          "A filesystem path is built from input — '../' can escape the intended directory.",
          "Resolve to an absolute path and verify it stays inside an allow-listed base directory."));
      }
    });
    return out;
  },
};

// 11. Unsafe C buffer functions --------------------------------------------
const unsafeBuffer: Rule = {
  id: "security.unsafe-buffer",
  title: "Unsafe buffer function",
  severity: "high",
  description: "C functions with no bounds checking (buffer overflow).",
  appliesTo: (l) => l === "c" || l === "cpp",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const crit = /\bgets\s*\(/;
      const mc = masked.match(crit);
      if (mc && mc.index !== undefined) {
        out.push(mk(unsafeBuffer.id, unsafeBuffer.title, "critical", i, mc.index, mc.index + mc[0].length,
          "gets() has no bounds checking — guaranteed overflow risk.",
          "Use fgets(buf, sizeof(buf), stdin)."));
      }
      const re = /\b(?:strcpy|strcat|sprintf|vsprintf)\s*\(/;
      const m = masked.match(re);
      if (m && m.index !== undefined) {
        out.push(mk(unsafeBuffer.id, unsafeBuffer.title, "high", i, m.index, m.index + m[0].length,
          "Unbounded string function can overflow the destination buffer.",
          "Use the bounded variants: strncpy / strncat / snprintf."));
      }
    });
    return out;
  },
};

// 12. Non-TLS HTTP URL ------------------------------------------------------
const httpUrl: Rule = {
  id: "security.http-url",
  title: "Insecure HTTP URL",
  severity: "low",
  description: "Cleartext http:// endpoint (non-localhost).",
  appliesTo: always,
  check(ctx) {
    const out: Finding[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      for (const hit of findAll(ctx.lines[i], /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+/g)) {
        if (/w3\.org|xmlns|schemas\.|\.dtd|example\.(?:com|org)/i.test(hit.match[0])) continue;
        out.push(mk(httpUrl.id, httpUrl.title, "low", i, hit.start, hit.end,
          "Cleartext HTTP endpoint — traffic can be read/modified in transit.",
          "Use https:// where the server supports it.",
          replaceFix("Switch to https://", i, hit.start, hit.start + "http://".length, "https://")));
      }
    }
    return out;
  },
};

// 13. PHP extract() of superglobals -----------------------------------------
const phpExtract: Rule = {
  id: "php.extract-superglobal",
  title: "extract() on user input",
  severity: "high",
  description: "extract() of $_GET/$_POST lets attackers set arbitrary variables.",
  appliesTo: (l) => l === "php",
  check(ctx) {
    const out: Finding[] = [];
    eachCodeLine(ctx, (raw, masked, i) => {
      const m = masked.match(/\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/);
      if (m && m.index !== undefined) {
        out.push(mk(phpExtract.id, phpExtract.title, "high", i, m.index, m.index + m[0].length,
          "extract() on a superglobal lets an attacker overwrite local variables.",
          "Read only the specific keys you need; never extract() request data."));
      }
    });
    return out;
  },
};

export const securityRules: Rule[] = [
  hardcodedSecret, sqlInjection, commandInjection, xss, dangerousEval,
  sslDisabled, weakRandom, weakHash, insecureDeser, pathTraversal,
  unsafeBuffer, httpUrl, phpExtract,
];
