// test/run.ts — dependency-free mini test runner for the analyzer core.
import { analyze, analyzeWithTrust } from "../src/core/analyzer";
import { RULES } from "../src/core/rules/index";
import { Finding, Language } from "../src/core/types";

let passed = 0, failed = 0;
const failures: string[] = [];

function run(name: string, fn: () => void) {
  try { fn(); passed++; }
  catch (e: any) { failed++; failures.push(`  x ${name}\n      ${e.message}`); }
}
function assert(cond: boolean, msg: string) { if (!cond) throw new Error(msg); }
function ids(code: string, lang: Language): string[] {
  return analyze(code, { language: lang }).map((f) => f.ruleId);
}
function expectRule(code: string, lang: Language, ruleId: string) {
  const got = ids(code, lang);
  assert(got.includes(ruleId), `expected '${ruleId}', got: [${got.join(", ") || "none"}]`);
}
function expectNoRule(code: string, lang: Language, ruleId: string) {
  const got = ids(code, lang);
  assert(!got.includes(ruleId), `did NOT expect '${ruleId}', got: [${got.join(", ")}]`);
}
function expectClean(code: string, lang: Language) {
  const got = ids(code, lang);
  assert(got.length === 0, `expected clean, got: [${got.join(", ")}]`);
}
function getFinding(code: string, lang: Language, ruleId: string): Finding {
  const f = analyze(code, { language: lang }).find((x) => x.ruleId === ruleId);
  assert(!!f, `rule '${ruleId}' not found`);
  return f!;
}

console.log("\n=== AI Code Skeptic — core test suite ===\n");

run("meta: unique rule ids", () => {
  const set = new Set(RULES.map((r) => r.id));
  assert(set.size === RULES.length, `duplicate ids: ${RULES.length} rules, ${set.size} unique`);
});
run("meta: >=25 rules", () => assert(RULES.length >= 25, `only ${RULES.length} rules`));

run("secrets: JS api key", () => expectRule(`const c = { apiKey: "sk-abcdef1234567890abcdef" };`, "javascript", "secrets.hardcoded"));
run("secrets: PHP password", () => expectRule(`$password = "SuperSecret123";`, "php", "secrets.hardcoded"));
run("secrets: AWS key", () => expectRule(`key = "AKIA1B2C3D4E5F6G7H8I"`, "python", "secrets.hardcoded"));
run("secrets: GitHub token", () => expectRule(`token = "ghp_aBcD1234567890aBcD1234567890aBcD12"`, "python", "secrets.hardcoded"));
run("secrets: Slack token", () => expectRule(`t = "xoxb-1234567890-abcdefghij"`, "python", "secrets.hardcoded"));
run("secrets: placeholder ignored", () => expectNoRule(`const apiKey = "your-api-key-here";`, "javascript", "secrets.hardcoded"));
run("secrets: env read ignored", () => expectNoRule(`const apiKey = process.env.API_KEY;`, "javascript", "secrets.hardcoded"));

run("sql: php concat", () => expectRule(`$q = "SELECT * FROM users WHERE id = " . $id;`, "php", "security.sql-injection"));
run("sql: js template", () => expectRule("const q = `SELECT * FROM u WHERE n = ${name}`;", "javascript", "security.sql-injection"));
run("sql: js plus", () => expectRule(`const q = "SELECT * FROM t WHERE x=" + inp;`, "javascript", "security.sql-injection"));
run("sql: python f-string", () => expectRule(`cur.execute(f"SELECT * FROM t WHERE id={uid}")`, "python", "security.sql-injection"));
run("sql: parameterized clean", () => expectNoRule(`$st = $pdo->prepare("SELECT * FROM users WHERE id = ?");`, "php", "security.sql-injection"));

run("cmd: python os.system+", () => expectRule(`os.system("rm " + path)`, "python", "security.command-injection"));
run("cmd: python shell=True", () => expectRule(`subprocess.run(cmd, shell=True)`, "python", "security.command-injection"));
run("cmd: php exec($)", () => expectRule(`exec("ping " . $host);`, "php", "security.command-injection"));
run("cmd: js template", () => expectRule("execSync(`git checkout ${branch}`);", "javascript", "security.command-injection"));
run("cmd: java exec+", () => expectRule(`Runtime.getRuntime().exec("ls " + dir);`, "java", "security.command-injection"));
run("cmd: go exec+", () => expectRule(`exec.Command("sh", "-c", "ls " + dir)`, "go", "security.command-injection"));
run("cmd: c system+", () => expectRule(`system("ping " + host);`, "c", "security.command-injection"));

run("xss: innerHTML", () => expectRule(`el.innerHTML = userInput;`, "javascript", "security.xss"));
run("xss: dangerouslySetInnerHTML", () => expectRule(`<div dangerouslySetInnerHTML={{__html: data}} />`, "typescript", "security.xss"));
run("xss: php echo $_GET", () => expectRule(`echo $_GET['name'];`, "php", "security.xss"));
run("xss: textContent clean", () => expectNoRule(`el.textContent = userInput;`, "javascript", "security.xss"));

run("eval: js", () => expectRule(`eval(userCode);`, "javascript", "security.eval"));
run("eval: python exec", () => expectRule(`exec(payload)`, "python", "security.eval"));
run("eval: ruby eval", () => expectRule(`eval(code)`, "ruby", "security.eval"));
run("eval: comment clean", () => expectNoRule(`// never use eval()`, "javascript", "security.eval"));
run("eval: string clean", () => expectNoRule(`const s = "eval(x)";`, "javascript", "security.eval"));

run("ssl: rejectUnauthorized false", () => expectRule(`const a = { rejectUnauthorized: false };`, "javascript", "security.ssl-disabled"));
run("ssl: python verify=False", () => expectRule(`requests.get(url, verify=False)`, "python", "security.ssl-disabled"));
run("ssl: go InsecureSkipVerify", () => expectRule(`tls.Config{InsecureSkipVerify: true}`, "go", "security.ssl-disabled"));

run("weak-random: js token", () => expectRule(`const token = Math.random().toString(36);`, "javascript", "security.weak-random"));
run("weak-random: java security", () => expectRule(`Random r = new Random(); // session token`, "java", "security.weak-random"));
run("weak-random: ui clean", () => expectNoRule(`const x = Math.random() * width;`, "javascript", "security.weak-random"));

run("weak-hash: python md5 password", () => expectRule(`h = hashlib.md5(password)`, "python", "security.weak-hash"));
run("weak-hash: java MD5", () => expectRule(`MessageDigest.getInstance("MD5")`, "java", "security.weak-hash"));

run("deser: python pickle.loads", () => expectRule(`obj = pickle.loads(data)`, "python", "security.insecure-deserialization"));
run("deser: python yaml.load", () => expectRule(`cfg = yaml.load(f)`, "python", "security.insecure-deserialization"));
run("deser: yaml.safe_load clean", () => expectNoRule(`cfg = yaml.safe_load(f)`, "python", "security.insecure-deserialization"));
run("deser: php unserialize", () => expectRule(`$o = unserialize($data);`, "php", "security.insecure-deserialization"));

run("path: php include $_GET", () => expectRule(`include($_GET['page']);`, "php", "security.path-traversal"));

run("buffer: gets", () => expectRule(`gets(buf);`, "c", "security.unsafe-buffer"));
run("buffer: strcpy", () => expectRule(`strcpy(dst, src);`, "cpp", "security.unsafe-buffer"));
run("buffer: snprintf clean", () => expectNoRule(`snprintf(buf, sizeof(buf), "%s", s);`, "c", "security.unsafe-buffer"));

run("http: insecure url", () => expectRule(`const u = "http://api.mybank.test/v1";`, "javascript", "security.http-url"));
run("http: localhost clean", () => expectNoRule(`const u = "http://localhost:3000";`, "javascript", "security.http-url"));
run("http: https clean", () => expectNoRule(`const u = "https://api.test/v1";`, "javascript", "security.http-url"));

run("php-extract: superglobal", () => expectRule(`extract($_POST);`, "php", "php.extract-superglobal"));

run("silent: js empty catch", () => expectRule(`try { f(); } catch (e) {}`, "javascript", "errors.silent-catch"));
run("silent: python except pass", () => expectRule(`try:\n    f()\nexcept Exception:\n    pass`, "python", "errors.silent-catch"));
run("silent: ruby empty rescue", () => expectRule(`begin\n  f\nrescue\nend`, "ruby", "errors.silent-catch"));
run("silent: js logged clean", () => expectNoRule(`try { f(); } catch (e) { console.error(e); }`, "javascript", "errors.silent-catch"));

run("broad: python except Exception", () => expectRule(`try:\n    f()\nexcept Exception:\n    handle()`, "python", "errors.broad-catch"));
run("broad: java catch Exception", () => expectRule(`try { f(); } catch (Exception ex) { log(ex); }`, "java", "errors.broad-catch"));
run("broad: python narrow clean", () => expectNoRule(`try:\n    f()\nexcept KeyError:\n    handle()`, "python", "errors.broad-catch"));

run("then-no-catch", () => expectRule(`fetch(url).then(r => r.json());`, "javascript", "js.unhandled-rejection"));
run("then-catch clean", () => expectNoRule(`get(url).then(r => r.json()).catch(e => log(e));`, "javascript", "js.unhandled-rejection"));
run("floating: fetch", () => expectRule(`fetch("/api/data");`, "javascript", "js.floating-promise"));
run("floating: awaited clean", () => expectNoRule(`await fetch("/api/data");`, "javascript", "js.floating-promise"));

run("go: ignored error", () => expectRule(`val, _ := doThing()`, "go", "go.ignored-error"));

run("debug: js console.log", () => expectRule(`console.log("here", data);`, "javascript", "quality.debug-leftover"));
run("debug: php var_dump", () => expectRule(`var_dump($result);`, "php", "quality.debug-leftover"));
run("debug: java printStackTrace", () => expectRule(`e.printStackTrace();`, "java", "quality.debug-leftover"));
run("debug: go fmt.Println", () => expectRule(`fmt.Println("debug", x)`, "go", "quality.debug-leftover"));

run("placeholder: TODO", () => expectRule(`// TODO: add validation`, "javascript", "quality.placeholder"));
run("placeholder: your code here", () => expectRule(`# your code here`, "python", "quality.placeholder"));

run("long-fn: js", () => {
  const body = Array.from({ length: 70 }, (_, k) => `  let v${k} = ${k};`).join("\n");
  expectRule(`function huge() {\n${body}\n}`, "javascript", "quality.long-function");
});
run("long-fn: short clean", () => expectNoRule(`function small() {\n  return 1;\n}`, "javascript", "quality.long-function"));
run("long-fn: python", () => {
  const body = Array.from({ length: 70 }, (_, k) => `    v${k} = ${k}`).join("\n");
  expectRule(`def huge():\n${body}`, "python", "quality.long-function");
});

run("empty-block: if {}", () => expectRule(`if (x) {}`, "javascript", "quality.empty-block"));

run("loose-eq: js ==", () => expectRule(`if (a == b) {}`, "javascript", "js.loose-equality"));
run("loose-eq: js !=", () => expectRule(`if (a != b) {}`, "javascript", "js.loose-equality"));
run("loose-eq: === clean", () => expectNoRule(`if (a === b) {}`, "javascript", "js.loose-equality"));
run("loose-eq: arrow clean", () => expectNoRule(`const f = (a) => a + 1;`, "javascript", "js.loose-equality"));
run("loose-eq: php ==", () => expectRule(`if ($a == $b) {}`, "php", "php.loose-equality"));

run("var: js var", () => expectRule(`var x = 5;`, "javascript", "js.var-usage"));
run("var: let clean", () => expectNoRule(`let x = 5;`, "javascript", "js.var-usage"));

run("mutable-default: []", () => expectRule(`def add(item, items=[]):\n    items.append(item)`, "python", "python.mutable-default"));
run("mutable-default: None clean", () => expectNoRule(`def add(item, items=None):\n    pass`, "python", "python.mutable-default"));

run("assert-validation: request", () => expectRule(`    assert request.user.is_admin`, "python", "python.assert-validation"));

run("java-string-eq: == literal", () => expectRule(`if (name == "admin") {}`, "java", "java.string-equality"));

run("rust: unwrap", () => expectRule(`let x = foo.unwrap();`, "rust", "rust.unwrap"));
run("rust: unsafe block", () => expectRule(`unsafe { *p = 1; }`, "rust", "rust.unsafe-block"));

run("trust: clean = 100 / Trusted", () => {
  const r = analyzeWithTrust(`function add(a, b) {\n  return a + b;\n}`, { language: "javascript" });
  assert(r.score === 100 && r.label === "Trusted", `got ${r.score}/${r.label}`);
});
run("trust: critical => Do not trust", () => {
  const r = analyzeWithTrust(`$q = "SELECT * FROM users WHERE id = " . $_GET['id'];`, { language: "php" });
  assert(r.counts.critical >= 1 && r.label === "Do not trust", `got ${r.counts.critical}/${r.label}`);
});
run("trust: never below 0", () => {
  const lines = Array.from({ length: 40 }, () => `eval(x); $q="SELECT a FROM b WHERE c="+y;`).join("\n");
  const r = analyzeWithTrust(lines, { language: "javascript" });
  assert(r.score >= 0 && r.score <= 100, `score out of range: ${r.score}`);
});
run("trust: fixable counted", () => {
  const r = analyzeWithTrust(`if (a == b) {}`, { language: "javascript" });
  assert(r.fixable >= 1, `expected fixable >=1, got ${r.fixable}`);
});

run("fix: == -> ===", () => {
  const f = getFinding(`if (a == b) {}`, "javascript", "js.loose-equality");
  assert(!!f.fix && f.fix.edits[0].newText === "===", `fix '${f.fix?.edits[0].newText}'`);
});
run("fix: verify=False -> True", () => {
  const f = getFinding(`requests.get(u, verify=False)`, "python", "security.ssl-disabled");
  assert(!!f.fix && f.fix.edits[0].newText.includes("verify=True"), "ssl fix wrong");
});
run("fix: mutable default -> None", () => {
  const f = getFinding(`def add(item, items=[]):\n    pass`, "python", "python.mutable-default");
  assert(!!f.fix && f.fix.edits[0].newText === "None", "mutable default fix wrong");
});
run("fix: http -> https", () => {
  const f = getFinding(`const u = "http://api.mybank.test/x";`, "javascript", "security.http-url");
  assert(!!f.fix && f.fix.edits[0].newText === "https://", "http fix wrong");
});
run("fix: innerHTML -> textContent", () => {
  const f = getFinding(`el.innerHTML = x;`, "javascript", "security.xss");
  assert(!!f.fix && f.fix.edits[0].newText === ".textContent", "xss fix wrong");
});

run("disable-line: suppresses rule", () => {
  expectNoRule(`if (a == b) {} // ai-skeptic-disable-line js.loose-equality`, "javascript", "js.loose-equality");
});
run("disable-line: all rules", () => {
  expectClean(`eval(x); // ai-skeptic-disable-line`, "javascript");
});
run("disable-next-line: suppresses", () => {
  expectNoRule(`// ai-skeptic-disable-next-line security.eval\neval(x);`, "javascript", "security.eval");
});
run("disable-line: python #", () => {
  expectNoRule(`eval(x)  # ai-skeptic-disable-line security.eval`, "python", "security.eval");
});

run("options: disabledRules", () => {
  const got = analyze(`if (a == b) {}`, { language: "javascript", disabledRules: ["js.loose-equality"] }).map((f) => f.ruleId);
  assert(!got.includes("js.loose-equality"), `not disabled: [${got.join(", ")}]`);
});
run("options: minSeverity filters", () => {
  const code = `console.log(x); eval(y);`;
  const all = analyze(code, { language: "javascript" });
  const high = analyze(code, { language: "javascript", minSeverity: "high" });
  assert(all.length > high.length, "minSeverity did not filter");
  assert(high.every((f) => ["high", "critical"].includes(f.severity)), "low findings remained");
});

run("positions: correct line", () => {
  const f = getFinding(`const ok = 1;\nconst bad = eval(p);`, "javascript", "security.eval");
  assert(f.line === 1, `expected line 1, got ${f.line}`);
});
run("positions: column at token", () => {
  const code = `const bad = eval(p);`;
  const f = getFinding(code, "javascript", "security.eval");
  assert(code.slice(f.column, f.endColumn).startsWith("eval"), `slice='${code.slice(f.column, f.endColumn)}'`);
});

run("integration: dirty PHP", () => {
  const code = [
    `<?php`,
    `$apiKey = "sk-1234567890abcdef1234";`,
    `$id = $_GET['id'];`,
    `$q = "SELECT * FROM users WHERE id = " . $id;`,
    `try { run($q); } catch (Exception $e) {}`,
    `echo $_GET['name'];`,
    `exec("ping " . $_GET['host']);`,
  ].join("\n");
  const r = analyzeWithTrust(code, { language: "php" });
  const set = new Set(r.findings.map((f) => f.ruleId));
  for (const id of ["secrets.hardcoded", "security.sql-injection", "security.xss", "security.command-injection", "errors.silent-catch"])
    assert(set.has(id), `missing ${id}`);
  assert(r.label === "Do not trust", `expected 'Do not trust', got '${r.label}'`);
});
run("integration: clean Python", () => {
  const code = [
    `import os`, ``,
    `def add(a, b):`, `    return a + b`, ``,
    `def safe_div(a, b):`, `    if b == 0:`, `        raise ValueError("zero")`, `    return a / b`,
  ].join("\n");
  expectClean(code, "python");
});

console.log(`\nResult: ${passed} passed, ${failed} failed.\n`);
if (failures.length) { console.log("Failures:\n" + failures.join("\n\n") + "\n"); process.exit(1); }
else { console.log("All tests green.\n"); process.exit(0); }
