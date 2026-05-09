import { AnalyzerRule, VulnerabilityType, RiskLevel, SecurityIssue } from '../types';
import { getTaintState, isNodeVulnerable } from '../taint';
import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;

export const rceRule: AnalyzerRule = {
  type: VulnerabilityType.RCE,
  run: (ast: any, code: string): SecurityIssue[] => {
    const issues: SecurityIssue[] = [];
    const state = getTaintState(ast);

    const isSource = (node: any) => {
      if (!node) return false;
      if (node.type === 'MemberExpression') {
        const objectName = node.object.name || (node.object.object && node.object.object.name);
        if (objectName === 'req' && (node.property.name === 'query' || node.property.name === 'body' || node.property.name === 'params')) {
          return true;
        }
      }
      return false;
    };

    const isSanitizer = (path: any) => false;

    const dangerousFunctions = ['eval', 'exec', 'execSync', 'spawn', 'spawnSync', 'Function'];

    traverse(ast, {
      CallExpression(path: any) {
        const { node } = path;
        const callee = node.callee;
        let fnName = '';
        
        if (callee.type === 'Identifier') fnName = callee.name;
        else if (callee.type === 'MemberExpression') fnName = callee.property.name || callee.property.value;

        if (dangerousFunctions.includes(fnName)) {
           node.arguments.forEach((arg: any) => {
             const { dangerous } = isNodeVulnerable(arg, path, state, isSource, isSanitizer);
             if (dangerous) {
               issues.push({
                 type: VulnerabilityType.RCE,
                 location: `Line ${node.loc?.start.line}`,
                 line: node.loc?.start.line || 0,
                 risk: RiskLevel.CRITICAL,
                 message: `Remote Code Execution detected via ${fnName}().`,
                 explanation: `Untrusted user input flows into ${fnName}().`,
                 fix_steps: ["Avoid shell execution.", "Use safe API alternatives."],
                 fix_code: fnName === 'spawn' ? `spawn('ls', [userInput], { shell: false })` : `exec(shellEscape(userInput), (err, stdout, stderr) => {`,
                 flow: ["Source: User Input", "Propagation: Variable Flow", `Sink: ${fnName}() Call`]
               });
             }
           });
        }
      }
    });

    return issues;
  }
};
