import { AnalyzerRule, VulnerabilityType, RiskLevel, SecurityIssue } from '../types';

export const regexRule: AnalyzerRule = {
  type: VulnerabilityType.MISC,
  run: (ast: any, code: string): SecurityIssue[] => {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    const patterns = [
      {
        regex: /password\s*=\s*['"][^'"]+['"]/i,
        risk: RiskLevel.MEDIUM,
        message: "Potential hardcoded credential detected.",
        explanation: "Statically defined passwords in source code can be easily extracted and lead to unauthorized access.",
        fix_steps: ["Move secrets to environment variables.", "Use a secrets management service."],
        fix_code: "// Use environment variables\nconst pass = process.env.DB_PASSWORD;"
      },
      {
        regex: /http:\/\//,
        risk: RiskLevel.LOW,
        message: "Insecure protocol (HTTP) used.",
        explanation: "HTTP traffic is unencrypted and vulnerable to man-in-the-middle attacks.",
        fix_steps: ["Replace http:// with https://.", "Enforce HSTS."],
        fix_code: "// Use HTTPS\nconst url = 'https://...';"
      },
      {
        regex: /TODO:\s*security/i,
        risk: RiskLevel.INFORMATIONAL,
        message: "Unresolved security note found.",
        explanation: "Development comments indicating security debt should be addressed before production.",
        fix_steps: ["Audit the specified code block.", "Resolve the listed security concern."],
        fix_code: "// SECURITY TASK: Resolve this debt\n// [ALREADY AUDITED]: ..."
      }
    ];

    lines.forEach((line, index) => {
      patterns.forEach(p => {
        if (p.regex.test(line)) {
          issues.push({
            type: VulnerabilityType.MISC,
            location: `Line ${index + 1}`,
            line: index + 1,
            risk: p.risk,
            message: p.message,
            explanation: p.explanation,
            fix_steps: p.fix_steps,
            fix_code: (p as any).fix_code
          });
        }
      });
    });

    return issues;
  }
};
