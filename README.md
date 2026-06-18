![version](https://img.shields.io/badge/version-2.0.0-3fb950)
![license](https://img.shields.io/badge/license-MIT-blue)
![languages](https://img.shields.io/badge/languages-11-58a6ff)
![rules](https://img.shields.io/badge/rules-30-orange)
![tests](https://img.shields.io/badge/tests-104%20passing-3fb950)

# 🕵️ AI Code Skeptic

A VS Code extension that **distrusts AI-generated code by default**. It scans your file with a battery of heuristics and highlights the spots where generated code statistically goes wrong — hardcoded secrets, swallowed errors, SQL/command injection, XSS, disabled TLS, unfinished stubs, and more. Every file gets a **Trust Score (0–100)**, and many issues come with a one-click **Quick Fix**.

> More code now ships than humans can review. The Skeptic points your eyes at the dangerous 10% first.

## Supported languages (11)
JavaScript · TypeScript (+ React) · Python · PHP · Java · C# · Go · Ruby · Rust · C · C++

## What it catches (30 rules)

### 🔒 Security
| id | Severity | What |
|----|----------|------|
| `secrets.hardcoded` | 🛑 critical | API keys, tokens, passwords, private keys in source |
| `security.sql-injection` | 🛑 critical | SQL built via concatenation / interpolation / f-strings |
| `security.command-injection` | 🛑 critical | Shell commands built from variables / `shell=True` |
| `security.xss` | 🔴 high | `innerHTML`, `dangerouslySetInnerHTML`, `echo $_GET` |
| `security.eval` | 🔴 high | `eval` / `exec` / `create_function` |
| `security.ssl-disabled` | 🔴 high | `verify=False`, `rejectUnauthorized:false`, `InsecureSkipVerify` |
| `security.insecure-deserialization` | 🔴 high | `pickle.loads`, `yaml.load`, `unserialize`, `readObject` |
| `security.weak-random` | 🟠 medium | Non-crypto RNG for tokens/passwords/salts |
| `security.weak-hash` | 🟠 medium | MD5 / SHA-1 in a security context |
| `security.path-traversal` | 🟠 medium | File path built from request input |
| `security.unsafe-buffer` | 🛑/🔴 | C `gets`/`strcpy`/`strcat`/`sprintf` |
| `security.http-url` | 🟡 low | Cleartext `http://` endpoints |
| `php.extract-superglobal` | 🔴 high | `extract($_GET/$_POST)` |

### ⚠️ Error handling
| id | Severity | What |
|----|----------|------|
| `errors.silent-catch` | 🔴 high | Empty `catch {}` / `except: pass` / empty `rescue` |
| `errors.broad-catch` | 🟠 medium | Catching the base `Exception`/`Throwable` |
| `js.unhandled-rejection` | 🟡 low | `.then` without `.catch` |
| `js.floating-promise` | 🟠 medium | Async call with no `await`/`then` |
| `go.ignored-error` | 🟠 medium | Error discarded with `_` |

### 🧹 Quality
| id | Severity | What |
|----|----------|------|
| `quality.debug-leftover` | 🟡 low | `console.log`, `var_dump`, `printStackTrace`, `fmt.Println`… |
| `quality.placeholder` | 🟠 medium | `TODO`, `FIXME`, `your code here`, `not implemented` |
| `quality.long-function` | 🟡 low | Functions over ~60 lines |
| `quality.empty-block` | 🟡 low | Empty `if`/`else`/`for`/`while` body |

### 🧩 Language footguns
| id | Severity | What |
|----|----------|------|
| `js.loose-equality` | 🟡 low | `==` / `!=` (auto-fix to `===`/`!==`) |
| `js.var-usage` | 🟡 low | `var` instead of `let`/`const` |
| `php.loose-equality` | 🟡 low | PHP `==` coercion |
| `python.mutable-default` | 🟠 medium | `def f(x=[])` (auto-fix to `None`) |
| `python.assert-validation` | 🟡 low | `assert` guarding real validation |
| `java.string-equality` | 🟠 medium | `==` on `String` |
| `rust.unwrap` | 🟡 low | `.unwrap()` / `.expect()` panics |
| `rust.unsafe-block` | 🟠 medium | `unsafe { }` blocks |

## ⚡ Quick Fixes
Issues with a lightning bolt are auto-fixable. Click the lightbulb (Ctrl+.) on the underlined code, or run **AI Skeptic: Fix all auto-fixable issues** to apply every safe fix in the file at once. Auto-fixable rules include: `==`→`===`, `var`→`let`, mutable default→`None`, `verify=False`→`verify=True`, `rejectUnauthorized:false`→`true`, `http://`→`https://`, `innerHTML`→`textContent`, empty `catch` → logged, and debug-line removal.

Every finding also offers **“Ignore '<rule>' on this line”**, which inserts an inline-disable comment.

## 🔕 Suppressing findings
```js
foo == bar;            // ai-skeptic-disable-line js.loose-equality
// ai-skeptic-disable-next-line security.eval
eval(code);
```
Omit the rule id to disable all rules on that line. Use `#` for Python/Ruby.

## Features
- Real-time analysis while typing (debounced) + on-demand command.
- In-editor squiggles (Problems panel) with a how-to-fix hint per finding.
- **Trust Score** in the status bar; click it for a full dark-themed report.
- Config: minimum severity, disabled rules, debounce delay, on/off toggle.

## Install (dev)
```bash
npm install
npm run compile      # builds to ./out
```
Press **F5** in VS Code to launch an Extension Development Host with the extension loaded.

Package & install as `.vsix`:
```bash
npm install -g @vscode/vsce
vsce package
code --install-extension ai-code-skeptic-2.0.0.vsix
```

## Commands (Ctrl+Shift+P)
- `AI Skeptic: Analyze current file`
- `AI Skeptic: Show file report`
- `AI Skeptic: Fix all auto-fixable issues`
- `AI Skeptic: Toggle real-time analysis`

## Settings
```jsonc
{
  "aiSkeptic.enableOnType": true,
  "aiSkeptic.debounceMs": 400,
  "aiSkeptic.minSeverity": "low",      // info|low|medium|high|critical
  "aiSkeptic.disabledRules": ["js.loose-equality"]
}
```

## Tests
The analyzer core is decoupled from the VS Code layer (`src/core/*` never imports `vscode`), so it runs in plain Node:
```bash
npm run build:core
npm test               # 104 tests
```

## Architecture
```
src/
  core/                  ← pure logic (tested without VS Code)
    types.ts
    helpers.ts           ← language detection, string/comment masking, inline-disable
    analyzer.ts          ← rule runner + Trust Score
    rules/
      security.ts        ← 13 security rules
      errors.ts          ← 5 error-handling rules
      quality.ts         ← 4 quality rules
      languages.ts       ← 8 language-specific rules
      index.ts           ← rule registry
  extension.ts           ← VS Code glue: diagnostics, status bar, Quick Fixes, report
test/run.ts              ← 104-test runner
```

## Extending
Add a `Rule` object to one of the `src/core/rules/*.ts` modules, export it in `index.ts`, and add a test in `test/run.ts`. The VS Code layer needs no changes. Attach a `fix` to make it auto-fixable.

## License
MIT © StillJun, 2026
