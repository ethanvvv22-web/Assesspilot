# Labelling worksheet: simply-vulnerable-notes

Source: `gitlab:gitlab-da/tutorials/security-and-governance/devsecops/simply-vulnerable-notes` at `632d9c83e5e6937c3695e6876cb4c0de2d1b9c51`

Use this to find where to look, then decide from the code yourself. The tools are often wrong.

Each cell lists one status per run (rules: 3 runs, Azure: 2 runs).

## CIA

| Dimension | Rules | Azure |
|---|---|---|
| confidentiality | Medium / Medium / Medium | High / Medium |
| integrity | High / High / High | High / Medium |
| availability | Unverified / Unverified / Unverified | Medium / Low |

## ISO27001

**5.15**: Access control

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/db.py:97` `query = "SELECT id, data FROM notes WHERE (secret IS FALSE AND id = %s)" % id` (Access control)

**5.17**: Authentication information

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/__init__.py:21` `users = {
    "admin": generate_password_hash("yeet")
} ` (Authentication information)

**5.34**: Privacy and protection of PII

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/routes.py:195` `        note.logger.info("Attempting to add note with msg: {}".format(msg))` (PII may be exposed in logs and admin output)

**8.2**: Privileged access rights

- Rules: needs_review / needs_review / needs_review
  - `notes/routes.py:84` `@note.route('/admin', methods=['GET', 'POST'])` (Privileged functions without role check)
- Azure: gap / gap
  - `notes/__init__.py:21` `users = {
    "admin": generate_password_hash("yeet")
} ` (Privileged access rights)

**8.5**: Secure authentication

- Rules: implemented / implemented / implemented
  - `notes/__init__.py:23` `"admin": generate_password_hash("yeet")` (Adaptive password hashing in use)
- Azure: gap / gap
  - `notes/__init__.py:7` `from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash` (Secure authentication)

**8.8**: Management of technical vulnerabilities

- Rules: implemented / implemented / implemented
  - `.gitlab-ci.yml:26` `- template: Jobs/Dependency-Scanning.latest.gitlab-ci.yml` (Dependency or security scanning in CI)
- Azure: implemented / not_evidenced
  - `docs/content/getting_started/lesson_4_setting_up_and_configuring_the_security_scanners_and_policies/_index.md:16` `We will go over the following scanners:

1. [Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user` (Vulnerability management integrated into CI/CD and project workflows)

**8.9**: Configuration management

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / implemented
  - `chart/templates/notes.yaml:19` `- name: "DB_ROOT_PWD"
            value:  {{ .Values.notes.dbrootpwd }}` (Secrets and configuration passed directly via Helm values/CI commands)

**8.12**: Data leakage prevention

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/db.py:27` `            note.logger.info("Connection set to: %s" % conn)` (Sensitive data and internal state are written to logs or output)

**8.15**: Logging

- Rules: implemented / implemented / implemented
  - `notes/db.py:16` `note.logger.info("No Database Name set, defaulting to 'default'")` (Security-relevant logging present)
- Azure: gap / gap
  - `notes/db.py:61` `    note.logger.info("Adding Note '{}'".format(str(notes)))` (Logging includes raw user content and secrets)

**8.20**: Networks security

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap
  - `docs/content/documentation/development_guide/_index.md:169` `| network-policies/      | Policies for limiting connectivity to pods |` (Network security controls unclear from provided manifests)

**8.24**: Use of cryptography

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review
  - `docs/content/documentation/development_guide/_index.md:159` `| config.py              | Contains the key used in securely signing the session cookie |` (Cryptographic usage and key management not fully visible)

**8.25**: Secure development life cycle

- Rules: implemented / implemented / implemented
  - `.gitlab-ci.yml:26` `- template: Jobs/Dependency-Scanning.latest.gitlab-ci.yml` (Dependency or security scanning in CI)
- Azure: implemented / implemented
  - `.gitlab-ci.yml:25` `include:
  - template: Jobs/Dependency-Scanning.latest.gitlab-ci.yml
  - template: Security/DAST.gitlab-ci.yml
  - templ` (Security integrated into development pipeline and workflows)

**8.28**: Secure coding

- Rules: gap / gap / gap
  - `notes/db.py:31` `c.execute("CREATE DATABASE IF NOT EXISTS %s" % db_name)` (SQL query built from strings)
- Azure: gap / gap
  - `notes/db.py:64` `        query = "INSERT INTO notes (data, secret) VALUES ('{}', {});".format(str(notes), str(admin))` (Multiple insecure coding patterns present (notably SQL injection))


## ASVS

**V2.1.1**: User-set passwords are at least 12 characters long

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/__init__.py:21` `users = {
    "admin": generate_password_hash("yeet")
} ` (User-set passwords are at least 12 characters long)

**V2.4.1**: Passwords are stored using an approved, salted, adaptive hashing function

- Rules: implemented / implemented / implemented
  - `notes/__init__.py:23` `"admin": generate_password_hash("yeet")` (Adaptive password hashing in use)
- Azure: implemented / implemented
  - `notes/__init__.py:8` `from werkzeug.security import generate_password_hash` (Passwords are stored using an approved, salted, adaptive hashing function)

**V3.4.1**: Cookie-based session tokens have the Secure attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review
  - `notes/__init__.py:16` `note = Flask(__name__)
note.config.from_object(Config` (No explicit evidence of Secure attribute configuration for session cookies)

**V3.4.2**: Cookie-based session tokens have the HttpOnly attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review
  - `notes/__init__.py:16` `note = Flask(__name__)
note.config.from_object(Config` (No explicit evidence of HttpOnly attribute configuration for session cookies)

**V4.1.1**: Access control rules are enforced on a trusted service layer

- Rules: needs_review / needs_review / needs_review
  - `notes/routes.py:84` `@note.route('/admin', methods=['GET', 'POST'])` (Privileged functions without role check)
- Azure: gap / gap
  - `notes/db.py:97` `query = "SELECT id, data FROM notes WHERE (secret IS FALSE AND id = %s)" % id` (Access control rules are enforced on a trusted service layer)

**V5.3.3**: Context-aware output escaping protects against reflected, stored and DOM-based XSS

- Rules: gap / gap / gap
  - `docs/assets/search.js:101` `div.innerHTML = content;` (Output rendered without escaping)
- Azure: gap / needs_review
  - `notes/routes.py:36` `                note_str = '%s | %s' % (_id, _note)` (User content is rendered into templates without explicit escaping)

**V5.3.4**: Database queries use parameterized queries, ORMs or are otherwise protected from injection

- Rules: gap / gap / gap
  - `notes/db.py:31` `c.execute("CREATE DATABASE IF NOT EXISTS %s" % db_name)` (SQL query built from strings)
- Azure: gap / gap
  - `notes/db.py:64` `        query = "INSERT INTO notes (data, secret) VALUES ('{}', {});".format(str(notes), str(admin))` (SQL queries are constructed via string formatting and are vulnerable to injectio)

**V5.3.8**: The application protects against OS command injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / not_evidenced
  - `scripts/reset_notes_table.sh:8` `DB_NAME=$(echo "$CI_COMMIT_REF_NAME" | sed 's/-//g')` (Shell script uses environment variables in commands; review required for CI/auto)

**V5.5.3**: Deserialization of untrusted data is avoided or protected

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**V6.2.2**: Industry-proven or government-approved cryptographic algorithms are used

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / not_evidenced
  - `docs/content/documentation/development_guide/_index.md:159` `| config.py              | Contains the key used in securely signing the session cookie |` (Use of industry-proven cryptography unclear)

**V6.4.1**: A secrets management solution is used to create, store and control access to secrets

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / gap
  - `notes/__init__.py:23` `    "admin": generate_password_hash("yeet")` (Secrets are present in code and environment variables only; no secret management)

**V7.1.1**: The application does not log credentials or payment details

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `notes/routes.py:195` `        note.logger.info("Attempting to add note with msg: {}".format(msg))` (Application logs potentially sensitive data (notes, secrets))

**V7.1.3**: The application logs security-relevant events

- Rules: implemented / implemented / implemented
  - `notes/db.py:16` `note.logger.info("No Database Name set, defaulting to 'default'")` (Security-relevant logging present)
- Azure: implemented / implemented
  - `notes/db.py:79` `    note.logger.info("Deleting Note with id: %s", id)` (Application logs many security-relevant events (adds, deletes, selects, errors))

**V9.2.1**: Connections use trusted TLS certificates that are validated

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `docs/content/getting_started/lesson_3_deploying_the_demo_application/_index.md:128` `Now let's use the ingress to access our application. With the default settings your application should be available at '` (Application served over plain HTTP and no TLS termination evidence)

**V12.3.1**: User-submitted filename metadata is not used directly by filesystems (path traversal)

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**V14.3.2**: Web or application server and framework debug modes are disabled in production

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented
  - `run.py:4` `if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    note.run(host='0.0.0.0', port=port, debug=Fa` (Application debug mode explicitly disabled)

**V14.5.3**: The CORS Access-Control-Allow-Origin header uses a strict allow list

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap
  - `chart/templates/notes.yaml:53` `nginx.ingress.kubernetes.io/cors-allow-headers: "X-Forwarded-For, X-Real-IP"` (CORS configuration lacks explicit allow-origin allow-list)


## NIST_AI_RMF

**GOVERN 1.1**: Legal and regulatory requirements involving AI are understood, managed and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**MAP 1.1**: Intended purposes, context and expected use of the AI system are understood and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**MEASURE 2.7**: AI system security and resilience are evaluated and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**MEASURE 2.10**: Privacy risk of the AI system is examined and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced

**MANAGE 4.1**: Post-deployment monitoring plans for the AI system are implemented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced
