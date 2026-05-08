import { AnalyzerRule, VulnerabilityType, RiskLevel, SecurityIssue } from '../types';
import traverse from '@babel/traverse';
import { getTaintState, isNodeVulnerable } from '../taint';

export const xssRule: AnalyzerRule = {
  type: VulnerabilityType.XSS,
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
      if (!node) return false;
      if (node.type === 'CallExpression') {
        const callee = node.callee;
        const name = callee.name || (callee.property && callee.property.name);
        const sanitizerKeywords = ['escape', 'sanitize', 'encodeURIComponent', 'DOMPurify', 'validator'];
        if (sanitizerKeywords.some(kw => name?.toLowerCase().includes(kw.toLowerCase()))) return true;

        if (callee.type === 'MemberExpression' && callee.property.name === 'replace') {
            const args = node.arguments;
            if (args.length >= 2 && args[0].type === 'RegExpLiteral') {
                const pattern = args[0].pattern;
                if (pattern.includes('<') || pattern.includes('>')) return true;
            }
        }
      }
      return false;
    };

    const xssSinks = ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'srcdoc', 'dangerouslySetInnerHTML', 'html'];

    traverse(ast, {
      AssignmentExpression(path: any) {
        const { node } = path;
        const left = node.left;
        let sinkName = '';
        
        if (left.type === 'MemberExpression') {
          sinkName = left.property.name || left.property.value;
        } else if (left.type === 'Identifier') {
          sinkName = left.name;
        }

        if (xssSinks.includes(sinkName) || String(sinkName).startsWith('on')) {
          const { dangerous, sanitized } = isNodeVulnerable(node.right, path, state, isSource, isSanitizer);
          if (dangerous && !sanitized) {
            issues.push({
              type: VulnerabilityType.XSS,
              location: `Line ${node.loc?.start.line}`,
              line: node.loc?.start.line || 0,
              risk: RiskLevel.CRITICAL,
              message: `XSS detected via ${sinkName} sink.`,
              explanation: `Untrusted user input flows into a dangerous DOM sink (${sinkName}) without proper sanitization. This allows an attacker to execute arbitrary JavaScript in the victim's browser context.`,
              fix_steps: [
                "Use .textContent or .innerText instead of .innerHTML.",
                "Sanitize all HTML content using a library like DOMPurify.",
                "Use framework-specific safe rendering methods (e.g., standard JSX template escaping)."
              ],
              fix_code: `// Safe approach using textContent\nelement.textContent = userInput;\n\n// Safe approach using DOMPurify\nelement.innerHTML = DOMPurify.sanitize(userInput);`,
              flow: ["Source: User Input", "Propagation: Variable Taint", `Sink: ${sinkName}`]
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

        const serverSinks = ['send', 'write', 'render', 'end'];
        const clientSinks = ['write', 'insertAdjacentHTML', 'parseFromString', 'html'];
        
        if (serverSinks.includes(fnName) || clientSinks.includes(fnName)) {
           node.arguments.forEach((arg: any) => {
             const { dangerous, sanitized } = isNodeVulnerable(arg, path, state, isSource, isSanitizer);
             if (dangerous && !sanitized) {
               issues.push({
                 type: VulnerabilityType.XSS,
                 location: `Line ${node.loc?.start.line}`,
                 line: node.loc?.start.line || 0,
                 risk: RiskLevel.CRITICAL,
                 message: `Reflected/Stored XSS detected via ${fnName}().`,
                 explanation: `The application renders untrusted user input directly into the HTML response via ${fnName}(), which can lead to Cross-Site Scripting.`,
                 fix_steps: [
                   "Escape all user-provided data before rendering.",
                   "Set appropriate Content-Type headers (e.g., text/plain if not HTML).",
                   "Implement a strict Content Security Policy (CSP)."
                 ],
                 fix_code: `// Express recommendation\nres.send(escapeHtml(userInput));`,
                 flow: ["Source: User Input", "Propagation: Logic Flow", `Sink: ${fnName}() Call`]
               });
             }
           });
        }
      }
    });

    return issues;
  }
};
