import { parse } from '@babel/parser';

export function parseCode(code: string): any {
  try {
    return parse(code, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
      allowImportExportEverywhere: true,
      errorRecovery: true,
    });
  } catch (err: any) {
    throw new Error(`AST Parsing Error: ${err.message}`);
  }
}
