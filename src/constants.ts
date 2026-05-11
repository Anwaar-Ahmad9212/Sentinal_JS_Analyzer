export const SAMPLE_CODE_RCE = `
const { exec, spawn } = require('child_process');
const express = require('express');
const vm = require('vm');
const app = express();

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  // VULNERABLE: Direct shell execution
  exec(cmd, (err, stdout, stderr) => {
    res.send(stdout);
  });
});

app.post('/spawn', (req, res) => {
  // VULNERABLE: spawn with shell:true
  spawn('ls', [req.body.dir], { shell: true });
});

app.get('/vm', (req, res) => {
   // VULNERABLE: VM sandbox escape potential
   vm.runInContext(req.query.code, {});
});

app.post('/timer', (req, res) => {
  // VULNERABLE: setTimeout with string
  setTimeout(req.body.task, 1000);
});
`;

export const SAMPLE_CODE_XSS = `
const express = require('express');
const app = express();

// --- Inter-procedural Flow (VULNERABLE) ---
function get_user(req) {
  return req.query.username
}

function render(data, res) {
  res.send("<h1>" + data + "</h1>")
}

app.get("/home", (req, res) => {
  const user = get_user(req)
  render(user, res)
})

// --- Deep Logical Flow (VULNERABLE - RCE) ---
function get_input(req) {
  return req.query.cmd
}

function prepare(data) {
  return data
}

function execute(command) {
  const { exec } = require("child_process")
  exec(command)
}

app.get("/admin", (req, res) => {
  const input = get_input(req)
  const processed = prepare(input)
  execute(processed)
  res.send("completed")
})

// --- Class Methods & Dynamic Imports (VULNERABLE) ---
class Controller {
  async handle(req, res) {
    const component = req.query.page;
    // Logical High: Taint through class and dynamic import
    await import(\`./pages/\${component}.js\`);
    res.send("Loaded " + component);
  }
}

// --- Nested Function Calls (VULNERABLE) ---
const utils = {
  wrap: (val) => \`<span>\${val}</span>\`,
  clean: (val) => val // "Fake" sanitizer
};

app.get("/nested", (req, res) => {
  // Logical Low: Taint flow through multiple wrapper calls
  res.send(utils.wrap(utils.clean(req.query.id)));
});

// --- Direct Sink (VULNERABLE) ---
app.get('/direct', (req, res) => {
  res.send(\`<div>\${req.query.user}</div>\`);
});

app.get('/redirect', (req, res) => {
  // VULNERABLE: Open Redirect / XSS
  res.redirect(req.query.url);
});
`;

export const SAMPLE_CODE_CSRF = `
const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());

// VULNERABLE: POST route without CSRF protection
app.post('/api/change-password', (req, res) => {
  const { newPassword } = req.body;
  // Logic to change password
  res.send('Password changed successfully');
});

app.delete('/api/delete-account', (req, res) => {
  // Logic to delete account
  res.send('Account deleted');
});
`;

export const SAMPLE_CODE_CLIENT = `
(function () {
  'use strict';
  var APP = window.__APP_INIT__ || {};
  
  function sanitize(html) {
    if (typeof DOMPurify === 'undefined') return '';
    return DOMPurify.sanitize(html, { ALLOWED_TAGS: ['b'] }); // "Safe" but we track it
  }

  function renderNoteContent() {
    var display = document.getElementById('note-display');
    var content = window.__NOTE_CONTENT__; // SOURCE: Tainted global
    if (!display || typeof content !== 'string') return;

    var clean = sanitize(content);
    display.innerHTML = clean; // SINK: innerHTML assignment
  }

  function loadCustomWidget(el) {
    var cfg = el.dataset.cfg; // SOURCE: Dataset attribute
    if (!cfg) return;
    var s = document.createElement('script');
    s.textContent = cfg; // PROPAGATION: Taint to script element
    document.head.appendChild(s); // SINK: Script injection
  }

  document.addEventListener('DOMContentLoaded', async function () {
    renderNoteContent();
  });
})();
`;

export const SECURE_CODE = `
const express = require('express');
const csrf = require('csurf');
const app = express();

app.use(csrf({ cookie: true }));

app.post('/api/safe', (req, res) => {
  res.send('Safe with CSRF token');
});

app.get('/safe-greet', (req, res) => {
  const name = String(req.query.name || '');
  // SAFE: Escaped or textContent (simulated here with simple string cast)
  res.send('Hello user');
});
`;
