# Security assessment: gitlab:gitlab-org/secure/gsoc-sast-benchmark/baselines/vuln-flask-web-app

| | |
|---|---|
| Status | **DRAFT — NOT APPROVED** |
| Revision | `b622a3257938a54e238b17558183a1c8287cd2c5` |
| Run | `525d13de4a8f` |
| Backend | azure |
| Generated | 2026-11-06 23:59 UTC |

> Drafted by AI agents. Every finding below cites code that was checked automatically; conclusions still require a qualified reviewer.

## 1. System overview

A small vulnerable Python/Flask web application intended as a proof-of-concept for security testing and SAST demonstrations. It exposes multiple example vulnerabilities and can be run locally or inside a Docker container.

- **language**: Python
- **framework**: Flask, Jinja2 (templating), Waitress (WSGI server)
- **datastore**: SQLite
- **auth**: API key (env VULN_FLASK_APP_API_KEY, cookie 'api_key'), Cookie-based session (user_id, session_token)
- **data type**: credentials, personal data (PII)
- **external service**: Google reCAPTCHA (site & secret keys), ImageMagick (convert), Remote URL fetching (urllib.request.urlopen)
- **entry point**: Flask app and routes (app.py)
- **deployment**: Docker + run scripts (run.prod.sh -> prod.py)

## 2. CIA classification

| Dimension | Level | Rationale | Evidence |
|---|---|---|---|
| Confidentiality | **Medium** | The repository contains hardcoded credentials, API-key configuration and handling of personal data (email/name) in request handling and templates, which could lead to user or org data disclosure. | `db_helper.py:14` — `        self.password = '[REDACTED:credential]'`<br>`db_helper.py:74` — `            cur.execute('INSERT INTO users VALUES (1, "admin", "e64b78fc3bc91bcbc7dc232ba8ec59e0", 1)') # password: Admin123`<br>`README.md:38` — `If you want to restrict the access to the app, just set the environment variable named 'VULN_FLASK_APP_API_KEY' with your secret:`<br>`README.md:44` — `Now, every request should include a cookie named 'api_key' with the value of the 'VULN_FLASK_APP_API_KEY' environment variable.`<br>`templates/ssrf.html:10` — `      <input class="input" type="email" name="email" id="email" placeholder="E-mail" required` |
| Integrity | **Medium** | Multiple code paths allow injection and unauthorised modification or access to data (SQL built from user input, insecure session handling allowing IDOR, command invocation on uploaded filenames, SSRF/path traversal), enabling modification or disclosure of records. | `vulns/sql_injection/sql_injection_login.py:20` — `    sql = f"SELECT * FROM users WHERE username='{username}' AND password='[REDACTED:credential]'"`<br>`vulns/idor/idor.py:33` — `    resp.set_cookie('user_id', str(user.id))`<br>`vulns/idor/idor.py:34` — `    resp.set_cookie('session_token', str(user.password))`<br>`vulns/idor/idor.py:40` — `    if request.cookies.get('session_token') != user.password:`<br>`vulns/file_upload/file_upload.py:48` — `    command = f'convert "{temp_upload_file_path}" -resize 50% "{resized_image_path}"' `<br>`vulns/ssrf/ssrf.py:35` — `    with urllib.request.urlopen(url) as f:` |
| Availability | **Medium** | The app exposes filesystem and external-request operations that can be abused to disrupt service (image processing via ImageMagick, arbitrary downloads, and database reset), which can cause noticeable outage or loss of service. | `vulns/file_upload/file_upload.py:48` — `    command = f'convert "{temp_upload_file_path}" -resize 50% "{resized_image_path}"' `<br>`vulns/ssrf/ssrf.py:35` — `    with urllib.request.urlopen(url) as f:`<br>`db_helper.py:62-64` — `    def reset_database(self):
        os.remove(self.DB_FILE_PATH)
        self.initialize()`<br>`templates/components/navbar.html:78` — `          <a class="button is-light" onclick="resetDatabase()" id="btnResetDatabase">` |

## 3. Findings

### Gaps (22)

**1. User-set passwords minimum length not enforced**

- Controls: ASVS V2.1.1 (User-set passwords are at least 12 characters long)
- The codebase contains example/actual user passwords shorter than 12 characters and no password length validation is visible.
- Recommendation: Enforce a minimum password length of at least 12 characters during account creation and password changes; add server-side validation and communicate requirements in the UI.
- Evidence: `templates/sql_injection/login.html:10` — `        Password: Admin123`
- Evidence: `templates/idor/idor_login.html:10` — `        Password: robso1980`

**2. Insecure password hashing used (MD5)**

- Controls: ASVS V2.4.1 (Passwords are stored using an approved, salted, adaptive hashing function)
- Passwords are hashed using MD5, which is not an approved, salted, adaptive hashing function.
- Recommendation: Use an approved, salted, adaptive hashing function such as bcrypt, scrypt, or Argon2 with appropriate work factors and unique salts per password.
- Evidence: `vulns/sql_injection/sql_injection_login.py:43` — `    md5_pass = hashlib.md5(password.encode('utf-8')).hexdigest()`
- Evidence: `vulns/idor/idor.py:14` — `    password = hashlib.md5(password.encode('utf-8')).hexdigest()`

**3. Session cookies set without Secure attribute**

- Controls: ASVS V3.4.1 (Cookie-based session tokens have the Secure attribute set)
- Cookie-based session tokens are set via set_cookie without specifying the Secure attribute, allowing them to be sent over insecure channels.
- Recommendation: Set the Secure attribute on session and authentication cookies (e.g., resp.set_cookie(..., secure=True)) and ensure the application is served over HTTPS.
- Evidence: `vulns/idor/idor.py:33` — `    resp.set_cookie('user_id', str(user.id))`
- Evidence: `vulns/idor/idor.py:34` — `    resp.set_cookie('session_token', str(user.password))`

**4. Session cookies set without HttpOnly attribute**

- Controls: ASVS V3.4.2 (Cookie-based session tokens have the HttpOnly attribute set)
- Cookie-based session tokens are set via set_cookie without the HttpOnly attribute, exposing them to access via client-side scripts.
- Recommendation: Set the HttpOnly attribute on session and authentication cookies (e.g., resp.set_cookie(..., httponly=True)) to mitigate access from client-side scripts.
- Evidence: `vulns/idor/idor.py:33` — `    resp.set_cookie('user_id', str(user.id))`
- Evidence: `vulns/idor/idor.py:34` — `    resp.set_cookie('session_token', str(user.password))`

**5. Access control enforced in application routes and is faulty**

- Controls: ASVS V4.1.1 (Access control rules are enforced on a trusted service layer)
- Access checks are implemented in route-level code and contain a logic bug (comparison to undefined variable), indicating access control is not enforced in a trusted, centralized service layer.
- Recommendation: Implement access control in a centralized, well-tested service layer or middleware. Fix logic errors and ensure checks validate authority against authenticated identity from a trusted session store.
- Evidence: `vulns/idor/idor.py:40` — `    if request.cookies.get('session_token') != user.password:`
- Evidence: `vulns/idor/idor.py:33` — `    resp.set_cookie('user_id', str(user.id))`

**6. Secrets are hardcoded in the repository rather than managed**

- Controls: ASVS V6.4.1 (A secrets management solution is used to create, store and control access to secrets)
- Secrets and credentials are stored in code (and files) rather than using a secrets management solution.
- Recommendation: Use a dedicated secrets management solution (e.g., vault, cloud KMS/secret manager) to create, store, and control access to secrets; remove hardcoded secrets from code and use environment variables or secure injection at runtime.
- Evidence: `api_keys.py:4` — `GOOGLE_RECAPTCHA_SECRET_KEY = '[REDACTED:credential]'`
- Evidence: `db_helper.py:11` — `        self.host = '10.0.0.99'`

**7. Access control missing / broken (IDOR)**

- Controls: ISO27001 5.15 (Access control)
- The application uses user-controlled cookies to select and display user profiles without proper authorization checks, enabling IDOR.
- Recommendation: Authorize access to user resources by verifying the authenticated user's identity against the requested resource on the server side; avoid using client-controlled identifiers without server-side ownership checks.
- Evidence: `vulns/idor/idor.py:44` — `    user_id = request.cookies.get('user_id')`
- Evidence: `vulns/idor/idor.py:46` — `    db_result = app.db_helper.execute_read(`

**8. Authentication information handled insecurely**

- Controls: ISO27001 5.17 (Authentication information)
- Authentication tokens are derived from stored password/hash and conveyed via cookies that lack security attributes; password hash is stored in cookie.
- Recommendation: Do not store password hashes in client-side cookies; use secure session tokens stored server-side or signed session cookies with appropriate attributes (Secure, HttpOnly, SameSite).
- Evidence: `vulns/idor/idor.py:34` — `    resp.set_cookie('session_token', str(user.password))`
- Evidence: `vulns/idor/idor.py:40` — `    if request.cookies.get('session_token') != user.password:`

**9. Privileged access rights are not properly enforced**

- Controls: ISO27001 8.2 (Privileged access rights)
- An administrative user exists in the database but the application does not enforce or demonstrate privilege checks when accessing resources.
- Recommendation: Enforce role-based access controls and check is_admin or equivalent attributes server-side for privileged operations; log and audit privileged actions.
- Evidence: `db_helper.py:74` — `            cur.execute('INSERT INTO users VALUES (1, "admin", "e64b78fc3bc91bcbc7dc232ba8ec59e0", 1)') # password: Admin123`
- Evidence: `vulns/idor/idor.py:44` — `    user_id = request.cookies.get('user_id')`

**10. Authentication implementation is insecure**

- Controls: ISO27001 8.5 (Secure authentication)
- Authentication uses weak hashing (MD5), stores password-derived tokens in cookies, and lacks secure cookie attributes, resulting in insecure authentication.
- Recommendation: Use secure authentication flows: strong password hashing (bcrypt/Argon2), server-side session management or signed tokens, and secure cookie attributes; avoid exposing password-derived values to the client.
- Evidence: `vulns/idor/idor.py:14` — `    password = hashlib.md5(password.encode('utf-8')).hexdigest()`
- Evidence: `vulns/idor/idor.py:34` — `    resp.set_cookie('session_token', str(user.password))`

**11. Context-aware output escaping missing / disabled leading to XSS**

- Controls: ASVS V5.3.3 (Context-aware output escaping protects against reflected, stored and DOM-based XSS)
- The codebase contains templates and storage of user input that render unsanitized data to users (reflected and stored XSS).
- Recommendation: Apply context-aware output encoding/escaping in templates, avoid disabling autoescaping, and sanitize/validate user input before storage and output. Use templating defaults (autoescape on) or explicit escaping functions for each context.
- Evidence: `templates/xss-reflected.html:14` — `      {{ request.args.get('search') }}`
- Evidence: `vulns/xssinjection/xss_stored.py:11-13` — `def xss_stored_api(request, app):
    message = request.form['message']
    result = app.db_helper.execute_write('INSERT INTO messages (message) VALUES (:msg)', { 'msg': message })`

**12. SQL queries built via string interpolation leading to SQL injection**

- Controls: ASVS V5.3.4 (Database queries use parameterized queries, ORMs or are otherwise protected from injection)
- Some handlers construct SQL queries by interpolating user input directly into SQL strings, which can lead to SQL injection.
- Recommendation: Use parameterized queries or an ORM consistently. Never concatenate or format SQL with untrusted input; pass user values via parameter placeholders.
- Evidence: `vulns/sql_injection/sql_injection_login.py:20` — `    sql = f"SELECT * FROM users WHERE username='{username}' AND password='[REDACTED:credential]'"`
- Evidence: `vulns/sql_injection/sql_injection_search.py:7` — `    sql = f"SELECT * FROM products WHERE name LIKE '%{search}%'"`

**13. OS commands invoked with user-controlled data**

- Controls: ASVS V5.3.8 (The application protects against OS command injection)
- The application builds shell command strings that include user-controlled filenames/paths and executes them via os.system, allowing command injection.
- Recommendation: Avoid shelling out with concatenated strings containing user input. Use safe APIs (e.g., subprocess.run with list args and shell=False) and validate/sanitize filenames. Prefer library functions over calling external commands.
- Evidence: `vulns/file_upload/file_upload.py:48-49` — `    command = f'convert "{temp_upload_file_path}" -resize 50% "{resized_image_path}"'
    os.system(command)`
- Evidence: `vulns/file_upload/file_upload.py:31` — `    os.system(f'mv {saved_file_path} {public_upload_file_path}')`

**14. User-supplied filenames and path parameters used directly, allowing path traversal**

- Controls: ASVS V12.3.1 (User-submitted filename metadata is not used directly by filesystems (path traversal))
- User-supplied filename metadata and query parameters are used to build filesystem paths without sanitization, enabling path traversal or saving files to unintended locations.
- Recommendation: Normalize and validate filenames; remove path components, reject suspicious input, use safe unique generated filenames, and enforce an allowlist of extensions. When serving files, map identifiers to canonical storage paths and prevent direct use of user-provided paths.
- Evidence: `vulns/file_upload/file_upload.py:42-44` — `    original_file_name = file.filename
    temp_upload_file_path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], original_file_name)
    file.save(temp_upload_file_path)`

**15. Multiple insecure coding practices present**

- Controls: ISO27001 8.28 (Secure coding)
- The repository contains multiple clear insecure coding patterns (unescaped template output, SQL built via string interpolation, shell commands using user input) indicating insecure coding practices.
- Recommendation: Adopt secure coding standards: validate and sanitize input, use parameterized queries/ORMs, avoid executing shell commands with untrusted data, keep template autoescaping enabled, and perform regular secure code reviews and SAST.
- Evidence: `templates/xss-reflected.html:14` — `      {{ request.args.get('search') }}`
- Evidence: `vulns/sql_injection/sql_injection_login.py:20` — `    sql = f"SELECT * FROM users WHERE username='{username}' AND password='[REDACTED:credential]'"`
- Evidence: `vulns/file_upload/file_upload.py:48-49` — `    command = f'convert "{temp_upload_file_path}" -resize 50% "{resized_image_path}"'
    os.system(command)`

**16. Use of weak cryptographic algorithm (MD5)**

- Controls: ASVS V6.2.2 (Industry-proven or government-approved cryptographic algorithms are used)
- The code uses MD5 for password hashing, which is not an industry-proven secure algorithm for password hashing and is considered broken for cryptographic use.
- Recommendation: Replace MD5 usage with a modern, approved password hashing algorithm (e.g., Argon2, bcrypt, scrypt, or use a vetted library such as passlib) and ensure algorithms follow current standards and guidelines.
- Evidence: `vulns/sql_injection/sql_injection_login.py:43` — `md5_pass = hashlib.md5(password.encode('utf-8')).hexdigest()`
- Evidence: `vulns/idor/idor.py:14` — `password = hashlib.md5(password.encode('utf-8')).hexdigest()`

**17. Hardcoded credentials and secrets present in repository**

- Controls: ISO27001 8.9 (Configuration management)
- The repository contains code snippets demonstrating hardcoded host, user, and password values and hardcoded API keys, indicating poor configuration management and secrets handling.
- Recommendation: Remove hardcoded credentials and secrets from code. Use environment variables or a secure secrets manager, rotate secrets, and add checks to prevent secrets being committed. Provide configuration examples (without secrets) and document secure configuration practices.
- Evidence: `README.md:66` — `self.host = '10.0.0.99'`
- Evidence: `README.md:69` — `self.password = '[REDACTED:credential]'`
- Evidence: `README.md:75` — `GOOGLE_RECAPTCHA_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'`

**18. Unrestricted outgoing network fetch (SSRF risk) and exposure of internal host**

- Controls: ISO27001 8.20 (Networks security)
- The application downloads arbitrary URLs provided by users using urllib.request.urlopen, enabling SSRF attacks. Additionally internal host values are present in code, which may indicate exposure of internal network resources.
- Recommendation: Validate and restrict outgoing URLs (allow-list hosts, block internal IP ranges), use safe download libraries with timeout and validation, and avoid exposing internal hostnames. Harden network controls and perform network-level restrictions (firewalls, egress rules).
- Evidence: `README.md:210` — `with urllib.request.urlopen(url) as f:`
- Evidence: `README.md:66` — `self.host = '10.0.0.99'`

**19. Insecure cryptographic usage for password hashing**

- Controls: ISO27001 8.24 (Use of cryptography)
- The code uses MD5 for hashing passwords in multiple places, which is insecure for cryptographic purposes and password storage.
- Recommendation: Use modern, purpose-built password hashing algorithms (Argon2, bcrypt, scrypt) and follow cryptographic best practices. Avoid general-purpose hashes like MD5 or SHA1 for password storage.
- Evidence: `vulns/sql_injection/sql_injection_login.py:43` — `md5_pass = hashlib.md5(password.encode('utf-8')).hexdigest()`
- Evidence: `vulns/idor/idor.py:14` — `password = hashlib.md5(password.encode('utf-8')).hexdigest()`

**20. Repository intentionally includes vulnerabilities and lacks SDLC artefacts**

- Controls: ISO27001 8.25 (Secure development life cycle)
- The project is explicitly a vulnerable PoC containing known security issues and the repository does not include evidence of secure development lifecycle practices (e.g., CI gated security checks, automated testing for security, security requirements, or remediation workflows).
- Recommendation: Adopt and document a secure development lifecycle: integrate security requirements, threat modeling, secure coding standards, automated security testing in CI (SAST/DAST), dependency scanning, and a vulnerability remediation process. Include CI configs and security policies in the repo for review.
- Evidence: `templates/home.html:8` — `This application contains some vulnerabilities hardcoded to be used as a PoC for SAST solutions.`
- Evidence: `README.md:62` — `### Hardcoded Credentials and Keys`

**21. User PII is read and rendered directly to templates and exposed via public URLs**

- Controls: ISO27001 5.34 (Privacy and protection of PII)
- The application reads user-supplied PII (email, name) from a form and renders it directly in a template. PII is also associated with a publicly accessible resource (downloaded image) which can further expose user data. These behaviors indicate a gap in protecting PII in the code shown.
- Recommendation: Avoid rendering or exposing PII unnecessarily. Store and display only what is required, apply access controls, redact or mask PII in views and logs, and ensure stored files are not publicly accessible unless explicitly required and authorized.
- Evidence: `vulns/ssrf/ssrf.py:14` — `    name = form['name']`
- Evidence: `templates/ssrf.html:19` — `        Email: {{ email }}`
- Evidence: `templates/ssrf.html:27` — `    <img src="{{ profile_picture_url }}" alt="">`

**22. Application downloads arbitrary external URLs and exposes them via a public URL (SSRF/data leakage risk)**

- Controls: ISO27001 8.12 (Data leakage prevention)
- The code fetches arbitrary URLs supplied by users and writes the content to a public uploads folder, then returns a public URL. This can leak internal or sensitive data reachable via SSRF to an external audience and exposes a direct data-leakage vector.
- Recommendation: Validate and restrict allowed hosts and schemes for remote fetches, implement allowlists, perform server-side fetches under restricted network/egress policies, avoid saving fetched content to public locations, and require authentication/authorization for access to fetched resources.
- Evidence: `vulns/ssrf/ssrf.py:35` — `    with urllib.request.urlopen(url) as f:`
- Evidence: `vulns/ssrf/ssrf.py:36` — `        download_image_path = f"{app.config['PUBLIC_UPLOAD_FOLDER']}/downloaded-image.png"`
- Evidence: `vulns/ssrf/ssrf.py:43` — `    public_url = f"{app.config['PUBLIC_UPLOADS_URL']}/downloaded-image.png"`

### Needs reviewer judgement (3)

**23. Potential development-mode configuration present; production debug settings unclear**

- Controls: ASVS V14.3.2 (Web or application server and framework debug modes are disabled in production)
- A development launch configuration sets FLASK_ENV to development which enables development behavior; there is no clear production configuration in the snapshot to confirm debug modes are disabled in production.
- Recommendation: Ensure production deployments set FLASK_ENV to 'production' (or appropriate env), disable Flask debug mode and interactive debugger, and verify server/startup scripts and WSGI server configurations do not enable debug features.
- Evidence: `.vscode/launch.json:12-15` — `"FLASK_APP": "app.py",
                "FLASK_ENV": "development"`
- Evidence: `.vscode/launch.json:16-19` — `"run",
                "--no-debugger"`

**24. Intentional vulnerable code present; vulnerability management practices not shown**

- Controls: ISO27001 8.8 (Management of technical vulnerabilities)
- The codebase is explicitly a PoC containing many vulnerabilities. The repository does not include evidence of vulnerability management processes (e.g., tracking, remediation, dependency updates, CVE monitoring) to show how technical vulnerabilities are managed over time.
- Recommendation: Establish and document vulnerability management processes: track discovered vulnerabilities, assign severity, remediate or mitigate in a timely manner, maintain a dependency update policy, and include CI checks for known vulnerabilities. Provide related artifacts (policy, issue trackers, CI jobs) in the repository or documentation.
- Evidence: `templates/home.html:8` — `This application contains some vulnerabilities hardcoded to be used as a PoC for SAST solutions.`
- Evidence: `README.md:60` — `## Vulns`

**25. Potential exposure of user credentials/PII in application rendering; no logging statements shown**

- Controls: ASVS V7.1.1 (The application does not log credentials or payment details)
- The code processes and renders user-supplied email and name values, but there are no logging statements in the provided code to confirm whether credentials or payment details are logged or not. Because PII is handled and rendered, further review is needed to ensure no logging of sensitive fields occurs elsewhere.
- Recommendation: Review the full codebase and runtime logging configuration to ensure credential and payment fields are never written to logs. If logging is required for troubleshooting, ensure sensitive fields (passwords, payment data, API keys) are redacted before logging.
- Evidence: `vulns/ssrf/ssrf.py:14` — `    name = form['name']`
- Evidence: `templates/ssrf.html:19` — `        Email: {{ email }}`

## 4. Control coverage

| Framework | Gap | Needs review | Implemented | Not evidenced |
|---|---|---|---|---|
| ISO27001 | 11 | 1 | 0 | 1 |
| ASVS | 11 | 2 | 0 | 4 |
| NIST_AI_RMF | 0 | 0 | 0 | 5 |

## 5. Quality and guardrail log

- Files analysed: 40; design documents: none
- Citations verified: 68/70
- Findings dropped for unverifiable evidence: 0
- CIA levels without verified evidence: 0
- Control claims discarded because nothing was cited: none
- Unknown control IDs removed: none
- Secrets redacted before analysis: 8
- Prompt-injection lines neutralised: 0
