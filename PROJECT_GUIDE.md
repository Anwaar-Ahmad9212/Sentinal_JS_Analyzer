# 🛡️ Advanced Web Security Analyzer: Engineering Deep Dive

This document provides a comprehensive technical breakdown of the **Advanced Web Security Analyzer**. It is designed to explain how the system transforms raw source code into a structured, searchable knowledge graph that detects deterministic exploit paths across function and variable boundaries.

---

## 1. The Core Engine: AST Transformation

The analyzer does not use basic text-search (Regex) for logic analysis. Instead, it employs **Static Analysis Security Testing (SAST)** techniques:

1.  **Parsing**: We use `@babel/parser` to convert JavaScript/TypeScript into an **Abstract Syntax Tree (AST)**.
2.  **Structural Intelligence**: The AST allows us to distinguish between a variable name, a function call, and a dangerous property access.
3.  **Traveral**: The engine walks through every "Node" (Statement, Expression, Declaration) to build a map of the application's intent.

---

## 2. The Taint Propagation Engine (`taint.ts`)

The "Taint Engine" is the central nervous system of the analyzer. It operates on the principle of **Data Flow Analysis**.

### A. Taint Sources (The Entry Points)
We track untrusted data entering the system from multiple "Sources":
*   **Server-Side**: `req.query`, `req.body`, `req.params`, `req.headers`, `req.cookies`.
*   **Client-Side**: `location.search`, `location.hash`, `document.cookie`.
*   **DOM Data**: `element.dataset`.
*   **Global Objects**: Custom globals like `window.__APP_INIT__`.
*   **Storage**: `localStorage.getItem()` and `sessionStorage.getItem()`.

### B. Nested Property Tracking
Historically, analyzers would lose track of `obj.data.cmd`. Our engine tracks **Nested Properties**. If `obj.data` is assigned tainted data, any future access to `obj.data` maintains its tainted status.

### C. Fixed-Point Iteration (Multi-Pass Analysis)
Code logic is often recursive or depends on code written "later" in the file. To handle this, the engine runs up to **5 sequential passes**. 
*   **Pass 1**: Identifies all function signatures and parameters.
*   **Pass 2-4**: Propagates taint across intermediate variables.
*   **Pass 5**: Resolves "Fixed-Point" state—where no more taints can be discovered regardless of more passes. This ensures we catch deep chains like `A -> B -> C -> D -> Sink`.

---

## 3. Interprocedural Analysis: Beyond the Function

Most basic scanners stop at the end of a function. Our analyzer implements **Interprocedural Flow**:

*   **Function Behavioral Summaries**: We calculate what a function *does* with its parameters. Does it return them? Does it pass them to a dangerous sink?
*   **Return Dependency Mapping**: If `function wrap(x) { return x }` is called with tainted data, the return value of that call is marked as tainted.
*   **Call Stack Simulation**: When an invocation like `exec(wrap(userInput))` occurs, the engine traverses the summary of `wrap` to determine if the tainted input actually reaches the `exec` sink.

---

## 4. Advanced Vulnerability Modeling

### Cross-Site Scripting (XSS)
*   **Context-Aware Sinks**: We track assignments to `.innerHTML`, `.outerHTML`, and `.srcdoc`.
*   **Framework Sinks**: Detection for React's `dangerouslySetInnerHTML` and Vue's `v-html` equivalents.
*   **Sanitization Heuristics**: The engine recognizes `DOMPurify.sanitize()` or manual string replacements like `.replace(/<|>/g, "")` as "Taint Clearers."

### Remote Code Execution (RCE)
*   **OS Command Injection**: Detects tainted data reaching `exec()`, `spawn()`, or `fork()`.
*   **Indirect Execution**: A critical detection for `window[user_input]()`. Even if the input isn't a direct command, using it to dynamically access global functions is flagged as Critical.
*   **Script Injection**: Tracks the creation of `<script>` elements and flags any assignment of user data to their `.textContent` or `.src`.

### Cross-Site Request Forgery (CSRF)
*   **Middleware Verification**: Analyzes the Express app's middleware stack. If it detects state-changing routes (`POST`, `PUT`, `DELETE`) without global CSRF middleware (like `csurf`), it triggers a high-severity alert.

---

## 5. Reporting & The "Detetion Flow"

Every issue discovered includes a **Logical Detection Flow** visualization on the dashboard. This shows the exact life of the vulnerability:
1.  **Source**: Where the attacker-controlled data starts.
2.  **Propagation**: Every variable or function call the data touched.
3.  **Sink**: The dangerous function where the data was finally executed.

This three-step visualization ensures that developers can trace and fix the root cause, rather than just patching the symptoms.

---

## 6. Scoring & Deduplication

*   **Deduplication Engine**: If the same logic path triggers multiple alerts across different layers, the analyzer merges them into a single unique "Issue" to prevent dashboard clutter.
*   **Safety Score**: A weighted percentage (0-100%) that reflects the overall security posture. Critical RCEs have the highest impact on the score, followed by XSS and configuration weaknesses.
