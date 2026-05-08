# 🛡️ Advanced Web Security Analyzer

![Security Analysis Dashboard](https://img.shields.io/badge/Security-AST--Based-blueviolet)
![Tech Stack](https://img.shields.io/badge/React-Vite-blue)
![Analysis](https://img.shields.io/badge/Taint--Analysis-Interprocedural-orange)

An enterprise-grade Static Analysis Security Testing (SAST) engine designed to detect deterministic exploit paths in JavaScript and TypeScript applications. This tool uses Abstract Syntax Tree (AST) traversal and multi-pass taint propagation to identify critical vulnerabilities like RCE, XSS, and CSRF.

## 🚀 Key Features

- **AST-Based Taint Engine**: Parses code into a structured tree to understand logical flow rather than simple pattern matching.
- **Interprocedural Analysis**: Tracks data flow across function boundaries and return statements.
- **Multi-Pass Fixed-Point Analysis**: Runs multiple iterations (up to 5 passes) to resolve deep dependency chains.
- **Browser-Aware Sinks**: Specifically modeled for modern web environments (DOM sinks, global property access, dataset, etc.).
- **Interactive Security Dashboard**: Real-time safety scoring, visual logical flow tracking, and suggested code fixes.
- **Zero-Trust Logic**: Distinguishes between raw user input and sanitization patterns (DOMPurify, regex escapes).

## 🔍 Vulnerability Coverage

| Category | Description |
| :--- | :--- |
| **Remote Code Execution (RCE)** | Detects OS command injection via `exec`, `spawn`, and indirect execution through global property access. |
| **Cross-Site Scripting (XSS)** | Identifies DOM-based, Reflected, and Stored XSS reaching sinks like `.innerHTML`, `.srcdoc`, or `dangerouslySetInnerHTML`. |
| **Cross-Site Request Forgery (CSRF)** | Analyzes middleware stacks to detect state-changing routes unprotected by anti-CSRF tokens. |
| **Sensitive Data Exposure** | Regex-based scanning for hardcoded secrets, keys, and insecure configuration patterns. |

## 🛠️ Technical Architecture

The analyzer operates through a multi-layered pipeline:
1. **Source Discovery**: Identifies inputs from `req.query`, `location.search`, `localStorage`, etc.
2. **Propagator**: Maps variable assignments and recursive property access (e.g., `obj.data.cmd`).
3. **Control Flow Analysis**: Handles branch sensitivity and function behavioral summaries.
4. **Sink Verification**: Confirms if tainted data reaches an executable or rendering sink without hitting a sanitizer.

## 📦 Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn

### Installation
```bash
# Install dependencies
npm install

# Start the interactive analyzer
npm run dev
```

## 🧠 Project Deep Dive
For a full technical explanation of the detection methods, fixed-point iteration, and logic flow, see the [PROJECT_GUIDE.md](./PROJECT_GUIDE.md).

---
*Made with ❤️ by Elliot Alderson 'Hello Friend'.*
