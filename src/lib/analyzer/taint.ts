import _traverse from '@babel/traverse';
const traverse = (_traverse as any).default || _traverse;

export interface TaintState {
  taintedVariables: Map<string, { sanitized: boolean; nestedProperties: Set<string> }>;
  taintedFunctions: Set<string>;
  functionParams: Map<string, string[]>;
  taintedParams: Map<string, Set<number>>;
  functionReturnParams: Map<string, number>; // New: tracks which param index a function returns
}

export function getTaintState(ast: any): TaintState {
  const taintedVariables = new Map<string, { sanitized: boolean; nestedProperties: Set<string> }>();
  const taintedFunctions = new Set<string>();
  const functionParams = new Map<string, string[]>();
  const taintedParams = new Map<string, Set<number>>();
  const functionReturnParams = new Map<string, number>();

  const isSource = (node: any): boolean => {
    if (!node) return false;
    
    // Server & Client sources
    if (node.type === 'MemberExpression') {
      let current = node;
      while (current && current.type === 'MemberExpression') {
        const propName = current.property.name || current.property.value;
        
        // Express sources
        if (current.object && current.object.name === 'req' && 
            (['query', 'body', 'params', 'headers', 'cookies'].includes(propName))) {
          return true;
        }

        // Client-side sources: location.search, location.hash, document.cookie
        if (current.object && current.object.name === 'location' && (['search', 'hash'].includes(propName))) return true;
        if (current.object && current.object.name === 'document' && propName === 'cookie') return true;
        
        // Dataset: el.dataset.X
        if (propName === 'dataset') return true;

        // Custom global sources often used in SPAs
        if (current.object && current.object.name === 'window' && String(propName).startsWith('__')) return true;

        current = current.object;
      }
      if (current && current.type === 'Identifier') {
         if (current.name === 'req') return true;
         if (current.name === 'location') return true;
      }
    }

    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
        const callee = node.callee;
        if (callee.object.name === 'localStorage' && callee.property.name === 'getItem') return true;
        if (callee.object.name === 'sessionStorage' && callee.property.name === 'getItem') return true;
    }

    // Call to a known tainted function
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
      if (taintedFunctions.has(node.callee.name)) return true;
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
              if (pattern.includes('<') || pattern.includes('>') || pattern.includes('&') || pattern.includes("'")) return true;
          }
      }
    }
    return false;
  };

  const runAnalysisPass = () => {
    let changed = false;

    traverse(ast, {
      FunctionDeclaration(path: any) {
        const { node } = path;
        if (node.id) {
          const name = node.id.name;
          const params = node.params.map((p: any) => p.name || (p.left && p.left.name) || (p.id && p.id.name));
          if (!functionParams.has(name)) {
            functionParams.set(name, params);
            changed = true;
          }
          
          path.traverse({
            ReturnStatement(retPath: any) {
              const arg = retPath.node.argument;
              if (arg) {
                if (isSource(arg) && !taintedFunctions.has(name)) {
                  taintedFunctions.add(name);
                  changed = true;
                }
                if (arg.type === 'Identifier') {
                  const pIdx = params.indexOf(arg.name);
                  if (pIdx !== -1 && functionReturnParams.get(name) !== pIdx) {
                    functionReturnParams.set(name, pIdx);
                    changed = true;
                  }
                  if (taintedVariables.has(arg.name) && !taintedFunctions.has(name)) {
                    taintedFunctions.add(name);
                    changed = true;
                  }
                }
              }
            }
          });
        }
      },
      VariableDeclarator(path: any) {
        const { node } = path;
        if (node.id.type === 'Identifier' && node.init) {
          const name = node.id.name;
          const checkTaint = (initNode: any): boolean => {
            if (isSource(initNode)) return true;
            if (initNode.type === 'Identifier' && taintedVariables.has(initNode.name)) return true;
            if (initNode.type === 'BinaryExpression' || initNode.type === 'LogicalExpression') return checkTaint(initNode.left) || checkTaint(initNode.right);
            if (initNode.type === 'TemplateLiteral') return initNode.expressions.some((e: any) => checkTaint(e));
            if (initNode.type === 'CallExpression' && initNode.callee.type === 'Identifier') {
              const fn = initNode.callee.name;
              if (taintedFunctions.has(fn)) return true;
              const retIdx = functionReturnParams.get(fn);
              if (retIdx !== undefined && initNode.arguments[retIdx] && checkTaint(initNode.arguments[retIdx])) return true;
            }
            return false;
          };

          if (checkTaint(node.init) && !taintedVariables.has(name)) {
            taintedVariables.set(name, { sanitized: isSanitizer(node.init), nestedProperties: new Set() });
            changed = true;
          }
        }
      },
      TemplateLiteral(path: any) {
        const node = path.node;
        // If any expression in the template is tainted, the whole literal is tainted
        const anyTainted = node.expressions.some((exp: any) => {
          if (exp.type === 'Identifier' && taintedVariables.has(exp.name)) return true;
          return false;
        });

        if (anyTainted && path.parentPath.isVariableDeclarator()) {
          const varName = path.parentPath.node.id.name;
          if (varName && !taintedVariables.has(varName)) {
            taintedVariables.set(varName, { sanitized: false, nestedProperties: new Set() });
            changed = true;
          }
        }
      },

      AssignmentExpression(path: any) {
        const { node } = path;
        if (node.left.type === 'MemberExpression') {
          const obj = node.left.object;
          const prop = node.left.property.name || node.left.property.value;
          if (obj.type === 'Identifier' && (isSource(node.right) || (node.right.type === 'Identifier' && taintedVariables.has(node.right.name)))) {
            if (!taintedVariables.has(obj.name)) {
              taintedVariables.set(obj.name, { sanitized: false, nestedProperties: new Set() });
              changed = true;
            }
            if (!taintedVariables.get(obj.name)?.nestedProperties.has(prop)) {
              taintedVariables.get(obj.name)?.nestedProperties.add(prop);
              changed = true;
            }
          }
        } else if (node.left.type === 'Identifier') {
          const name = node.left.name;
          if ((isSource(node.right) || (node.right.type === 'Identifier' && taintedVariables.has(node.right.name))) && !taintedVariables.has(name)) {
            taintedVariables.set(name, { sanitized: isSanitizer(node.right), nestedProperties: new Set() });
            changed = true;
          }
        }
      },
      CallExpression(path: any) {
        const { node } = path;
        const fnName = node.callee.name || (node.callee.property && node.callee.property.name);
        if (fnName) {
          node.arguments.forEach((arg: any, index: number) => {
            const checkArg = (a: any): boolean => {
              if (a.type === 'Identifier' && taintedVariables.has(a.name)) return true;
              if (a.type === 'MemberExpression' && a.object.type === 'Identifier' && taintedVariables.get(a.object.name)?.nestedProperties.has(a.property.name)) return true;
              if (a.type === 'CallExpression' && a.callee.type === 'Identifier' && taintedFunctions.has(a.callee.name)) return true;
              return false;
            };
            if (checkArg(arg) && !taintedParams.get(fnName)?.has(index)) {
              if (!taintedParams.has(fnName)) taintedParams.set(fnName, new Set());
              taintedParams.get(fnName)?.add(index);
              changed = true;
            }
          });
        }
      }
    });

    return changed;
  };

  // Run analysis multiple times to catch multi-level dependencies
  let maxPasses = 5;
  while (maxPasses > 0 && runAnalysisPass()) {
    maxPasses--;
  }

  return {
    taintedVariables,
    taintedFunctions,
    functionParams,
    taintedParams,
    functionReturnParams
  };
}

export function isNodeVulnerable(
    node: any, 
    path: any, 
    state: TaintState,
    isSource: (node: any) => boolean,
    isSanitizer: (node: any) => boolean
): { dangerous: boolean; sanitized: boolean } {
  let dangerous = false;
  let sanitized = false;

  const check = (n: any) => {
    if (!n) return;
    if (isSource(n)) dangerous = true;
    if (n.type === 'Identifier') {
        const tVar = state.taintedVariables.get(n.name);
        if (tVar) {
            dangerous = true;
            if (tVar.sanitized) sanitized = true;
        }
    }
    if (n.type === 'MemberExpression' && n.object.type === 'Identifier') {
        const tVar = state.taintedVariables.get(n.object.name);
        const prop = n.property.name || n.property.value;
        if (tVar && tVar.nestedProperties.has(prop)) {
            dangerous = true;
        }
    }
        
        // Parameter Check
        const parentFn = path.getFunctionParent();
        if (parentFn && parentFn.node && (parentFn.node.id || parentFn.parentPath?.node?.id)) {
            const fnNode = parentFn.node;
            const fnName = fnNode.id?.name || parentFn.parentPath?.node?.id?.name;
            if (fnName) {
                const params = state.functionParams.get(fnName);
                const tIndexSet = state.taintedParams.get(fnName);
                if (params && tIndexSet) {
                    const idx = params.indexOf(n.name);
                    if (idx !== -1 && tIndexSet.has(idx)) dangerous = true;
                }
            }
        }
    if (isSanitizer(n)) sanitized = true;
    
    if (n.type === 'BinaryExpression' || n.type === 'LogicalExpression') {
        check(n.left);
        check(n.right);
    }
    if (n.type === 'TemplateLiteral') {
        n.expressions.forEach(check);
    }
    if (n.type === 'ArrayExpression') {
        n.elements.forEach(check);
    }
    if (n.type === 'CallExpression') {
        const fnName = n.callee.name || (n.callee.property && n.callee.property.name);
        if (fnName && state.taintedFunctions.has(fnName)) dangerous = true;
        n.arguments.forEach(check);
    }
  };

  check(node);
  return { dangerous, sanitized };
}
