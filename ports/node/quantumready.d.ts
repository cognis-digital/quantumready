// TypeScript declarations for the quantumready Node port.
// Lets the .mjs surface be consumed and type-checked from TypeScript projects.

export const TOOL_NAME: string;
export const TOOL_VERSION: string;

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  label: string;
  where: string;
  line: number;
  match: string;
  recommend: string;
}

export interface Readiness {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  severity_counts: Record<Severity, number>;
  pqc_present: boolean;
}

export const RULES: ReadonlyArray<[string, Severity, RegExp, string, string]>;

export function scanText(text: string, path?: string): Finding[];
export function scanPath(target: string): Finding[];
export function readiness(findings: Finding[]): Readiness;
export function toJSON(findings: Finding[]): string;
export function run(argv: string[]): number;
