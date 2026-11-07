# Labelling worksheet: pygoat

Source: `https://github.com/adeyosemanputra/pygoat.git` at `2aa4cc14f251e4a780e94e200aed6b36a5b15c21`

Use this to find where to look, then decide from the code yourself. The tools are often wrong.

Each cell lists one status per run (rules: 3 runs, Azure: 3 runs).

## CIA

| Dimension | Rules | Azure |
|---|---|---|
| confidentiality | High / High / High | High / High / High |
| integrity | High / High / High | High / High / High |
| availability | Medium / Medium / Medium | High / Medium / High |

## ISO27001

**5.15**: Access control

- Rules: implemented / implemented / implemented
  - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:80` `@login_required` (Server-side access control checks)
- Azure: gap / gap / gap
  - `Solutions/solution.md:186` `Every time a valid user logs in,the user session is set with a cookie called 'admin'` (Access control)

**5.17**: Authentication information

- Rules: gap / gap / gap
  - `challenge/labs/business_logic_lab/app.py:5` `app.secret_key = "[REDACTED:credential]"` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/templates/index.html:121` `<pre class="code">$argon2id$v=19$m=65536,t=3,p=4$Ub40KHiEbH9I3Bsd4VHQDA$4zsIHDmAbejFJmaZq8a2yVIJdHvfylDlQ85w3YRLMSQ</pre` (Authentication information)

**5.34**: Privacy and protection of PII

- Rules: needs_review / needs_review / needs_review
  - `dockerized_labs/auth_failure_lab/app.py:96` `email = request.form.get("email")` (Personal data processed)
- Azure: gap / gap / gap
  - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:65` `                credit_card="4111111111111111",  # test visa card number lol` (PII stored and exposed in cleartext and returned in API responses)

**8.2**: Privileged access rights

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:43` `ADMIN_USERNAME = "admin_pygoat@pygoat.com"` (Privileged access rights)

**8.5**: Secure authentication

- Rules: implemented / implemented / implemented
  - `dockerized_labs/auth_failure_lab/app.py:4` `from argon2 import PasswordHasher` (Adaptive password hashing in use)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:98` `# Vulnerable: Short OTP, no rate limiting
            otp = str(random.randint(100, 999))
            if email == "admin` (Secure authentication)

**8.8**: Management of technical vulnerabilities

- Rules: implemented / implemented / implemented
  - `dockerized_labs/dependency_attack_lab/templates/lab.html:55` `<h4>Package Safety Check API</h4>` (Dependency or security scanning in CI)
- Azure: gap / gap / implemented
  - `CHANGELOG.md:91` `- Multi-stage, hardened root Docker build on 'python:3.11-slim-bookworm' (#392, #404). This also fixes the build failure` (Some vulnerability management activity is present but unresolved technical issue)

**8.9**: Configuration management

- Rules: gap / gap / gap
  - `challenge/labs/bopla_lab/app.py:152` `app.run(host='0.0.0.0', port=8080, debug=True)` (Debug mode enabled)
- Azure: gap / gap / gap
  - `dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8` `SECRET_KEY = "[REDACTED:credential]"` (Insecure or incomplete configuration management (hard-coded secrets, permissive )

**8.12**: Data leakage prevention

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:127` `# Intentionally insecure - for teaching purposes!` (Multiple endpoints and client-side code leak sensitive data)

**8.15**: Logging

- Rules: implemented / implemented / implemented
  - `dockerized_labs/a9_uckv_lab/app.py:11` `logger = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: gap / gap / gap
  - `challenge/views.py:29` `    except Exception as e:` (Logging practices may expose sensitive information and lack controls)

**8.20**: Networks security

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/sec_misconfig/app.py:69` `        "auth_service": "http://internal-auth.prod:8080",` (Network-related configuration exposes internal endpoints and uses permissive hos)

**8.24**: Use of cryptography

- Rules: gap / gap / gap
  - `challenge/labs/business_logic_lab/app.py:5` `app.secret_key = "[REDACTED:credential]"` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `dockerized_labs/crypto_failure_lab/README.md:7` `1. Weak Hashing (e.g., MD5)` (Insecure cryptography usage and plaintext secrets present)

**8.25**: Secure development life cycle

- Rules: implemented / implemented / implemented
  - `dockerized_labs/dependency_attack_lab/templates/lab.html:55` `<h4>Package Safety Check API</h4>` (Dependency or security scanning in CI)
- Azure: gap / gap / implemented
  - `CHANGELOG.md:95` `- Added PR and issue templates (#398), a pre-commit hook for formatting, and 'KNOWN_ISSUES.md' (#318).` (Some SDLC practices exist but insecure defaults remain in code)

**8.28**: Secure coding

- Rules: gap / gap / gap
  - `dockerized_labs/a9_uckv_lab/templates/lab2.html:54` `<code>image.size[0] if True else exec('import os; os.system("ls")')</code></li>` (OS command built from input)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:12` `app.config["SECRET_KEY"] = "insecure-secret-key"  # Intentionally weak secret key` (Multiple deliberate insecure coding patterns present)


## ASVS

**V2.1.1**: User-set passwords are at least 12 characters long

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/broken_auth_lab/templates/secure-fix.html:35` `'min_length': 8,` (User-set passwords minimum length)

**V2.4.1**: Passwords are stored using an approved, salted, adaptive hashing function

- Rules: gap / gap / gap
  - `dockerized_labs/broken_auth_lab/app.py:103` `token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()` (Weak hash used for passwords or integrity)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:81` `ph = PasswordHasher()` (Password storage uses approved salted adaptive hashing)

**V3.4.1**: Cookie-based session tokens have the Secure attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:105` `response.set_cookie("email", email)` (Cookie-based session tokens have Secure attribute)

**V3.4.2**: Cookie-based session tokens have the HttpOnly attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / needs_review
  - `dockerized_labs/auth_failure_lab/app.py:105` `response.set_cookie("email", email)` (Cookie-based session tokens have HttpOnly attribute)

**V4.1.1**: Access control rules are enforced on a trusted service layer

- Rules: implemented / implemented / implemented
  - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:80` `@login_required` (Server-side access control checks)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:216` `# Vulnerable: Session information stored in cookie without signature` (Access control enforced on a trusted service layer)

**V5.3.3**: Context-aware output escaping protects against reflected, stored and DOM-based XSS

- Rules: gap / gap / gap
  - `challenge/labs/bopla_lab/templates/base.html:25` `themeToggle.innerHTML = newTheme === 'dark' ? '☀️' : '🌙';` (Output rendered without escaping)
- Azure: gap / gap / gap
  - `dockerized_labs/software_integrity_lab/app.py:62` `# Intentionally vulnerable to XSS that can modify download link` (Output escaping not consistently applied; intentional XSS sinks present)

**V5.3.4**: Database queries use parameterized queries, ORMs or are otherwise protected from injection

- Rules: implemented / implemented / implemented
  - `challenge/labs/business_logic_lab/templates/solution.html:99` `existing = db.query(AppliedCoupons).filter_by(` (Parameterised queries / ORM in use)
- Azure: implemented / implemented / implemented
  - `dockerized_labs/auth_failure_lab/app.py:137` `user = Admin.query.filter_by(username=username).first()` (ORM usage for database access)

**V5.3.8**: The application protects against OS command injection

- Rules: gap / gap / gap
  - `dockerized_labs/a9_uckv_lab/templates/lab2.html:54` `<code>image.size[0] if True else exec('import os; os.system("ls")')</code></li>` (OS command built from input)
- Azure: gap / gap / gap
  - `dockerized_labs/command_injection_lab/app.py:28` `# Intentionally vulnerable command execution` (Command execution and eval with user input present (command injection/code execu)

**V5.5.3**: Deserialization of untrusted data is avoided or protected

- Rules: gap / gap / gap
  - `dockerized_labs/a9_uckv_lab/app.py:62` `data = yaml.load(file.stream, Loader=yaml.Loader)` (Unsafe deserialisation or eval)
- Azure: gap / gap / gap
  - `dockerized_labs/software_integrity_lab/app.py:43` `admin = pickle.loads(
                token
            )  # Intentionally vulnerable to pickle deserialization` (Insecure deserialization via pickle from untrusted cookie)

**V6.2.2**: Industry-proven or government-approved cryptographic algorithms are used

- Rules: gap / gap / gap
  - `dockerized_labs/broken_auth_lab/app.py:103` `token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()` (Weak hash used for passwords or integrity)
- Azure: gap / gap / gap
  - `dockerized_labs/crypto_failure_lab/README.md:7` `1. Weak Hashing (e.g., MD5)` (Use of weak or deprecated cryptographic algorithms present in codebase)

**V6.4.1**: A secrets management solution is used to create, store and control access to secrets

- Rules: gap / gap / gap
  - `challenge/labs/business_logic_lab/app.py:5` `app.secret_key = "[REDACTED:credential]"` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `dockerized_labs/auth_failure_lab/app.py:12` `app.config["SECRET_KEY"] = "insecure-secret-key"  # Intentionally weak secret key` (Use of a secrets management solution)

**V7.1.1**: The application does not log credentials or payment details

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/sensitive_data_exposure/templates/profile.html:128` `User's full credit card: {{ user_data.credit_card }}` (Logging or client-side console/storage exposes credentials and payment details)

**V7.1.3**: The application logs security-relevant events

- Rules: implemented / implemented / implemented
  - `dockerized_labs/a9_uckv_lab/app.py:11` `logger = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: gap / gap / gap
  - `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:85` `        # TODO: add audit logging here someday` (Missing audit/security logging for authentication and critical events)

**V9.2.1**: Connections use trusted TLS certificates that are validated

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / gap / needs_review
  - `dockerized_labs/sec_misconfig/app.py:134` `if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5009)` (No enforced TLS certificate validation; services run without TLS in many places)

**V12.3.1**: User-submitted filename metadata is not used directly by filesystems (path traversal)

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `dockerized_labs/ssrf_lab/app.py:20` `# Vulnerable implementation - allows directory traversal` (User-supplied filename used directly when reading files (path traversal))

**V14.3.2**: Web or application server and framework debug modes are disabled in production

- Rules: gap / gap / gap
  - `challenge/labs/bopla_lab/app.py:152` `app.run(host='0.0.0.0', port=8080, debug=True)` (Debug mode enabled)
- Azure: gap / gap / gap
  - `dockerized_labs/sec_misconfig/app.py:8` `app.debug = True  # Intentionally enabled for Lab 2` (Debug mode is enabled in application code and settings)

**V14.5.3**: The CORS Access-Control-Allow-Origin header uses a strict allow list

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced


## NIST_AI_RMF

**GOVERN 1.1**: Legal and regulatory requirements involving AI are understood, managed and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**MAP 1.1**: Intended purposes, context and expected use of the AI system are understood and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**MEASURE 2.7**: AI system security and resilience are evaluated and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**MEASURE 2.10**: Privacy risk of the AI system is examined and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**MANAGE 4.1**: Post-deployment monitoring plans for the AI system are implemented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced
