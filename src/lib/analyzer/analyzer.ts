import { parseCode } from './parser';
import { rceRule } from './rules/rce';
import { xssRule } from './rules/xss';
import { csrfRule } from './rules/csrf';
import { regexRule } from './rules/regex';
import { AnalysisReport, SecurityIssue, RiskLevel, VulnerabilityType } from './types';

export function analyzeCode(code: string): AnalysisReport {
  try {
    const ast = parseCode(code);
    const rules = [rceRule, xssRule, csrfRule, regexRule];
    
    let allIssues: SecurityIssue[] = [];
    
    rules.forEach(rule => {
      const issues = rule.run(ast, code);
      allIssues = [...allIssues, ...issues];
    });

    // Deduplicate issues by line and type
    const uniqueIssues = allIssues.filter((issue, index, self) =>
      index === self.findIndex((t) => (
        t.line === issue.line && t.type === issue.type && t.message === issue.message
      ))
    );

    // Sort by line number
    uniqueIssues.sort((a, b) => a.line - b.line);

    // Calculate stats
    const stats = {
      total: uniqueIssues.length,
      critical: uniqueIssues.filter(i => i.risk === RiskLevel.CRITICAL).length,
      high: uniqueIssues.filter(i => i.risk === RiskLevel.HIGH).length,
      medium: uniqueIssues.filter(i => i.risk === RiskLevel.MEDIUM).length,
      low: uniqueIssues.filter(i => i.risk === RiskLevel.LOW).length,
      informational: uniqueIssues.filter(i => i.risk === RiskLevel.INFORMATIONAL).length,
      score: 0
    };

    // Recommended Percentage Calculation Logic
    let totalDeduction = 0;
    
    uniqueIssues.forEach(issue => {
      let deduction = 0;
      
      // Vulnerability Type specific deductions
      if (issue.type === VulnerabilityType.RCE) {
        if (issue.risk === RiskLevel.CRITICAL) deduction = 35;
        else if (issue.risk === RiskLevel.HIGH) deduction = 30;
      } else if (issue.type === VulnerabilityType.XSS) {
        if (issue.risk === RiskLevel.CRITICAL) deduction = 25;
        else if (issue.risk === RiskLevel.HIGH) deduction = 20;
      } else if (issue.type === VulnerabilityType.CSRF) {
        if (issue.risk === RiskLevel.HIGH) deduction = 18;
      }

      // If no type-specific deduction was found, use general risk categories
      if (deduction === 0) {
        switch (issue.risk) {
          case RiskLevel.CRITICAL: deduction = 35; break;
          case RiskLevel.HIGH: deduction = 20; break;
          case RiskLevel.MEDIUM: deduction = 10; break;
          case RiskLevel.LOW: deduction = 5; break;
          case RiskLevel.INFORMATIONAL: deduction = 2; break;
        }
      }
      
      totalDeduction += deduction;
    });

    stats.score = Math.max(0, 100 - totalDeduction);

    return {
      issues: uniqueIssues,
      stats
    };
  } catch (err: any) {
    throw err;
  }
}
