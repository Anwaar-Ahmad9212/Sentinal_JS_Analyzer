import { AnalyzerRule, VulnerabilityType, RiskLevel, SecurityIssue } from '../types';
import traverse from '@babel/traverse';
import { getTaintState, isNodeVulnerable } from '../taint';

export const rceRule: AnalyzerRule = {
  type: VulnerabilityType.RCE,
  run: (ast: any, code: string): SecurityIssue[] => {
    const issues: SecurityIssue[] = [];
    const state = getTaintState(ast);

    const isSource = (node: any): boolean => {
      if (!node) return false;
      if (node.type === 'MemberExpression') {
        let current = node;
        while (current && current.type === 'MemberExpression') {
          const propName = current.property.name || current.property.value;
          if (current.object && current.object.name === 'req' && 
              (['query', 'body', 'params', 'headers'].includes(propName))) {
            return true;
          }
          if (current.object && current.object.name === 'location' && (['search', 'hash'].includes(propName))) return true;
          if (propName === 'dataset') return true;
          if (current.object && current.object.name === 'window' && propName.startsWith('__')) return true;
          current = current.object;
        }
        if (current && current.type === 'Identifier') {
           if (current.name === 'req' || current.name === 'location') return true;
        }
      }
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
        if (state.taintedFunctions.has(node.callee.name)) return true;
      }
      return false;
    };

    const isSanitizer = (node: any): boolean => {
      return false;
    };

    const dangerousFunctions = ['eval', 'Function', 'setTimeout', 'setInterval', 'exec', 'execSync', 'spawn', 'spawnSync', 'fork'];
    
    // Track script elements created via createElement
    const scriptElements = new Set<string>();

    traverse(ast, {
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.init && node.init.type === 'CallExpression' && 
            node.init.callee.type === 'MemberExpression' &&
            node.init.callee.property.name === 'createElement' &&
            node.init.arguments[0]?.value === 'script') {
          if (node.id.type === 'Identifier') {
            scriptElements.add(node.id.name);
          }
        }
      },
      AssignmentExpression(path: any) {
        const { node } = path;
        const left = node.left;
        
        // Command construction analysis e.g. cmd = "cat " + user_input
        if (left.type === 'Identifier') {
           const { dangerous } = isNodeVulnerable(node.right, path, state, isSource, isSanitizer);
           if (dangerous && node.right.type === 'BinaryExpression' && node.right.operator === '+') {
              // Potential command injection prep
           }
        }

        if (left.type === 'MemberExpression' && scriptElements.has(left.object.name) && 
            (['textContent', 'innerHTML', 'src'].includes(left.property.name))) {
          const { dangerous } = isNodeVulnerable(node.right, path, state, isSource, isSanitizer);
          if (dangerous) {
            issues.push({
              type: VulnerabilityType.RCE,
              location: `Line ${node.loc?.start.line}`,
              line: node.loc?.start.line || 0,
              risk: RiskLevel.CRITICAL,
              message: "Untrusted Script Content Injection.",
              explanation: `User-controlled data is being assigned to a <script> element's ${left.property.name}. This is a critical Remote Code Execution risk as the content will execute in the user's browser.`,
              fix_steps: [
                "Avoid creating scripts dynamically from user input.",
                "Use static scripts or robust templating.",
                "Enforce a strict Content Security Policy (CSP)."
              ],
              fix_code: "// Avoid dynamic scripts\nconsole.log('Use static entry points');",
              flow: ["Source: User Input", "Propagation: Assignment", `Sink: Script ${left.property.name}`]
            });
          }
        }

        // Indirect execution e.g. window[user_input](data)
        if (left.type === 'MemberExpression' && (left.object.name === 'window' || left.object.name === 'globalThis')) {
           const { dangerous } = isNodeVulnerable(left.property, path, state, isSource, isSanitizer);
           if (dangerous) {
              issues.push({
                type: VulnerabilityType.RCE,
                location: `Line ${node.loc?.start.line}`,
                line: node.loc?.start.line || 0,
                risk: RiskLevel.CRITICAL,
                message: "Indirect Execution via Dynamic Property Access.",
                explanation: `Untrusted input is used to access a property on a global object (window/globalThis). This allow an attacker to call arbitrary global functions like eval or alert.`,
                fix_steps: ["Avoid dynamic property access on global objects.", "Use an allowlist of permitted function names."],
                fix_code: `const allowed = { func1, func2 };\nif (allowed[userInput]) allowed[userInput]();`,
                flow: ["Source: User Input", `Sink: Global Property Access (${left.object.name})`]
              });
           }
        }
      },
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
                 explanation: `Untrusted user input flows into a function that executes code or shell commands (${fnName}). This is a critical vulnerability that can lead to complete system compromise.`,
                 fix_steps: [
                   "Never pass user input directly to eval() or exec().",
                   "Use child_process.spawn() with separate arguments instead of exec().",
                   "Use a library to properly escape shell arguments."
                 ],
                 fix_code: `// Safe approach using spawn\nconst { spawn } = require('child_process');\nspawn('ls', [userInput]);`,
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
