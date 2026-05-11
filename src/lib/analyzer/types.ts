/**
 * Vulnerability types and risk levels
 */
export enum VulnerabilityType {
  RCE = 'RCE',
  XSS = 'XSS',
  CSRF = 'CSRF',
  MISC = 'MISC',
}

export enum RiskLevel {
  INFORMATIONAL = 'INFORMATIONAL',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export interface Location {
  line: number;
  column: number;
}

export interface SecurityIssue {
  type: VulnerabilityType;
  location: string;
  line: number;
  risk: RiskLevel;
  message: string;
  explanation: string;
  fix_steps: string[];
  fix_code: string;
  flow?: string[]; // Source -> Proc -> Sink
}

export interface AnalysisReport {
  issues: SecurityIssue[];
  stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    score: number; // 0-100 (100 is secure)
  };
}

export interface AnalyzerRule {
  type: VulnerabilityType;
  run: (ast: any, code: string) => SecurityIssue[];
}
