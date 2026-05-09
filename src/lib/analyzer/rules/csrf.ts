import { AnalyzerRule, VulnerabilityType, RiskLevel, SecurityIssue } from '../types';
import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;

export const csrfRule: AnalyzerRule = {
  type: VulnerabilityType.CSRF,
  run: (ast: any, code: string): SecurityIssue[] => {
    const issues: SecurityIssue[] = [];
    let hasProtection = false;
    const unsafeRoutes: any[] = [];

    traverse(ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;
        const name = callee.name || (callee.property && callee.property.name);

        // Detect Middleware (csurf, lusca, custom csrf)
        if (name === 'use') {
          node.arguments.forEach((arg: any) => {
            const isCsrfMiddleware = (n: any): boolean => {
              if (!n) return false;
              if (n.type === 'CallExpression') {
                const cn = n.callee.name || (n.callee.property && n.callee.property.name);
                return ['csrf', 'csurf', 'lusca'].includes(cn?.toLowerCase());
              }
              return false;
            };
            if (isCsrfMiddleware(arg)) hasProtection = true;
          });
        }

        // Detect state-changing routes
        const methods = ['post', 'put', 'delete', 'patch'];
        if (callee.type === 'MemberExpression' && methods.includes(callee.property?.name)) {
           unsafeRoutes.push({
             method: callee.property.name.toUpperCase(),
             line: node.loc?.start.line || 0
           });
        }
      }
    });

    if (!hasProtection && unsafeRoutes.length > 0) {
      unsafeRoutes.forEach(route => {
        issues.push({
          type: VulnerabilityType.CSRF,
          location: `Line ${route.line}`,
          line: route.line,
          risk: RiskLevel.HIGH,
          message: `Missing CSRF protection on ${route.method} route.`,
          explanation: "Cross-Site Request Forgery (CSRF) allows an attacker to induce users to perform actions they do not intend to perform. State-changing routes (POST, PUT, DELETE) must be protected by anti-CSRF tokens.",
          fix_steps: [
            "Install a CSRF protection middleware like 'csurf'.",
            "Ensure the middleware is applied globally or to all state-changing routes.",
            "Verify that forms include the anti-CSRF token in a hidden field or header."
          ],
          fix_code: "const csrf = require('csurf');\napp.use(csrf({ cookie: true }));",
          flow: [`Route: ${route.method} endpoint`, "Protection Check: Global CSRF middleware missing"]
        });
      });
    }

    return issues;
  }
};
