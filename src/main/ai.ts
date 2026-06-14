import { Finding } from './db';

interface AIChatResponse {
  answer: string;
  codeSnippet?: string;
  language?: string;
}

export class AIService {
  
  // Custom intelligence mapping to return rich recommendations based on finding types
  generateRemediationAdvice(finding: Finding): AIChatResponse {
    const titleLower = finding.title.toLowerCase();
    
    if (titleLower.includes('content-security-policy') || titleLower.includes('csp')) {
      return {
        answer: `### Risk Analysis
The Content-Security-Policy (CSP) header is a powerful security layer that restricts the resources (such as JavaScript, CSS, Images) that the browser is allowed to load for a given page. Without CSP, the application is highly vulnerable to **Cross-Site Scripting (XSS)** and **Clickjacking** attacks.

### Remediation Guidance
You should configure your web server (Nginx, Apache, IIS) or application framework (Node/Express, Django) to send a robust CSP header.

For Express apps, you can use the \`helmet\` package which sets up a baseline CSP automatically.`,
        codeSnippet: `// 1. Install helmet: npm install helmet
import express from 'express';
import helmet from 'helmet';

const app = express();

// Enable Helmet to set security headers including CSP
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "https://trustedscripts.com"],
      "style-src": ["'self'", "https://fonts.googleapis.com"],
      "object-src": ["'none'"],
      "upgrade-insecure-requests": [],
    },
  },
}));`,
        language: 'javascript'
      };
    }

    if (titleLower.includes('strict-transport-security') || titleLower.includes('hsts')) {
      return {
        answer: `### Risk Analysis
Strict-Transport-Security (HSTS) prevents protocol downgrade attacks (shifting from HTTPS to insecure HTTP) and cookie hijacking. When HSTS is active, the browser automatically converts all unencrypted links to secure HTTPS links before making the connection.

### Remediation Guidance
Configure HSTS with a generous \`max-age\` (OWASP recommends 2 years / 63072000 seconds), enforce it for subdomains, and register for preloading.`,
        codeSnippet: `# Nginx Configuration (add to your server block)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Node.js/Express (using Helmet)
app.use(helmet.hsts({
  maxAge: 63072000,
  includeSubDomains: true,
  preload: true
}));`,
        language: 'nginx'
      };
    }

    if (titleLower.includes('cookie') && (titleLower.includes('secure') || titleLower.includes('httponly'))) {
      return {
        answer: `### Risk Analysis
Session cookies or sensitive tokens sent without **HttpOnly** can be accessed by malicious client scripts (XSS). Without the **Secure** flag, cookies can be transmitted in plain text over unencrypted networks (Wi-Fi, HTTP), enabling Man-in-the-Middle (MitM) hijacking.

### Remediation Guidance
Configure cookie serialization to force both flags. If cookies are used cross-domain, ensure proper **SameSite** configurations (\`Lax\` or \`Strict\`).`,
        codeSnippet: `// Express Session Cookie Configuration
import session from 'express-session';

app.use(session({
  secret: 'super-secure-session-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,  // Prevents JavaScript access
    secure: true,    // Forces HTTPS transmission
    sameSite: 'lax', // Protects against CSRF
    maxAge: 3600000  // 1 hour expiry
  }
}));`,
        language: 'javascript'
      };
    }

    if (titleLower.includes('aws') || titleLower.includes('secret') || titleLower.includes('key')) {
      return {
        answer: `### Risk Analysis
Hardcoding access keys or credentials directly into source code repositories or configuration files poses a severe risk. Attackers scrape public and private repositories using automated scrapers to find keys. Once compromised, these keys allow unauthorized access to cloud services, leading to host hijacking, database exfiltration, or massive cloud billing.

### Remediation Guidance
1. **Rotate/Revoke immediately:** Generate a new key and delete the old one.
2. **Environment Variables:** Load key configurations dynamically at runtime.
3. **Use Secret Managers:** Use services like AWS Secrets Manager or HashiCorp Vault.`,
        codeSnippet: `// Securely reading environment variables (Node.js)
// 1. Create a .env file (AND ADD IT TO .gitignore):
// AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
// AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

// 2. Load and use via dotenv:
import dotenv from 'dotenv';
import { S3Client } from "@aws-sdk/client-s3";

dotenv.config();

const s3 = new S3Client({
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  },
  region: "us-east-1"
});`,
        language: 'javascript'
      };
    }

    if (titleLower.includes('prototype pollution') || titleLower.includes('lodash') || titleLower.includes('minimist')) {
      return {
        answer: `### Risk Analysis
Prototype Pollution allows an attacker to inject property settings into the base object class constructor. When properties are merged without sanitization, an attacker can modify \`Object.prototype\`. This can lead to bypasses in authorization checks, denial of service, or Remote Code Execution (RCE).

### Remediation Guidance
Upgrade the affected package. For npm, run \`npm update\` or explicitly pin to a secure version in your dependencies lockfile. In custom code, freeze the prototype or use maps without prototypes (\`Object.create(null)\`).`,
        codeSnippet: `// Fixing Prototype Pollution in custom deep merge functions:
function safeMerge(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      // Prevent proto or constructor overrides
      if (key === '__proto__' || key === 'constructor') {
        continue;
      }
      
      if (typeof source[key] === 'object' && target[key] === 'object') {
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}`,
        language: 'javascript'
      };
    }

    // Default Fallback Advice
    return {
      answer: `### Risk Analysis
This finding represents a security configuration discrepancy or code-level flaw that violates development best practices.

### Remediation Guidance
1. Audit the source code where this dependency or configuration is imported.
2. Ensure you validate inputs, restrict directory access, and apply the Principle of Least Privilege.
3. Keep library dependencies updated to their latest stable patches.`,
      codeSnippet: `// General secure configuration template
const securityOptions = {
  sanitizeInputs: true,
  enableSsl: true,
  maxConnections: 100,
  timeoutMs: 3000
};`,
      language: 'javascript'
    };
  }

  // General Chat processor
  processChat(message: string, contextFinding?: Finding): AIChatResponse {
    const msg = message.toLowerCase();
    
    if (contextFinding) {
      // Provide target remediation for context finding
      return this.generateRemediationAdvice(contextFinding);
    }

    // Generic security questions
    if (msg.includes('xss') || msg.includes('cross-site scripting')) {
      return {
        answer: `### Cross-Site Scripting (XSS)
XSS occurs when an application includes untrusted data in a web page without proper validation or escaping.

**Types:**
1. **Stored XSS:** Malicious script is permanently stored on the database.
2. **Reflected XSS:** Script is part of the request (e.g. search query).
3. **DOM-based XSS:** Vulnerability is in the client-side JavaScript.

**Defenses:**
* Context-aware HTML Escaping / Encoding
* Content Security Policy (CSP) headers
* Use modern template engines (React, Angular) which auto-escape by default`,
        codeSnippet: `// Sanitizing HTML input in Node/Express (DOMPurify/jsdom)
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const dirtyInput = "<script>alert('xss')</script><p>Clean text</p>";
const cleanHTML = DOMPurify.sanitize(dirtyInput);
console.log(cleanHTML); // Outputs: "<p>Clean text</p>"`,
        language: 'javascript'
      };
    }

    if (msg.includes('csrf') || msg.includes('cross-site request forgery')) {
      return {
        answer: `### Cross-Site Request Forgery (CSRF)
CSRF forces an end-user to execute unwanted actions on a web application in which they're currently authenticated.

**Defenses:**
1. **SameSite Cookie Attribute:** Set to \`Lax\` or \`Strict\` to block third-party requests.
2. **Anti-CSRF Tokens:** Use cryptographically secure tokens associated with the user session, validated on every POST/PUT/DELETE request.`,
        codeSnippet: `// CSRF protection in Express using double-submit cookies or csurf
import csurf from 'csurf';
import cookieParser from 'cookie-parser';

app.use(cookieParser());
const csrfProtection = csurf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
  // Pass token to view
  res.render('send', { csrfToken: req.csrfToken() });
});`,
        language: 'javascript'
      };
    }

    if (msg.includes('injection') || msg.includes('sql')) {
      return {
        answer: `### Injection Attacks (SQLi, Command Injection)
Injection vulnerabilities occur when untrusted user input is concatenated directly into SQL queries or OS commands.

**Defenses:**
* Use **Parameterized Queries** (Prepared Statements).
* Avoid building shell strings; use native library parameters instead.
* Sanitize with strict allow-list regexes.`,
        codeSnippet: `// Secure SQL Query using Prepared Statements
import mysql from 'mysql2/promise';

const connection = await mysql.createConnection({ host: 'localhost', user: 'root', database: 'test' });

// SECURE: Parameters are sent separately from the SQL syntax
const userId = req.query.id;
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);`,
        language: 'javascript'
      };
    }

    // Default response
    return {
      answer: `### Dragon AI Security Assistant
Hello! I am your security remediation assistant. You can ask me about:
* **OWASP Top 10** vulnerabilities (XSS, Injection, CSRF, etc.)
* **Secure configurations** for Nginx, Apache, or Docker
* **Vulnerability fixes** (How to secure headers, cookie flags, dependency patches)

Select a vulnerability from the **Vulnerability Explorer** to ask me specific questions about its remediation.`,
      codeSnippet: `// Example: Secure code is clean code
function secureCheck(input) {
  if (!input || typeof input !== 'string') {
    throw new Error('Invalid Input');
  }
  return input.trim();
}`,
      language: 'javascript'
    };
  }
}

export const aiService = new AIService();
