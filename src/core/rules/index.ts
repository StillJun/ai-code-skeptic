// src/core/rules/index.ts
import { Rule } from "../types";
import { securityRules } from "./security";
import { errorRules } from "./errors";
import { qualityRules } from "./quality";
import { languageRules } from "./languages";

export const RULES: Rule[] = [
  ...securityRules,
  ...errorRules,
  ...qualityRules,
  ...languageRules,
];

export const RULE_INDEX: Record<string, Rule> = Object.fromEntries(RULES.map((r) => [r.id, r]));
