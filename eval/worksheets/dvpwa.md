# Labelling worksheet: dvpwa

Source: `https://github.com/anxolerd/dvpwa.git` at `a1d8f89fac2e57093189853c6527c2b01fc1d9c1`

Use this to find where to look, then decide from the code yourself. The tools are often wrong.

Each cell lists one status per run (rules: 3 runs, Azure: 3 runs).

## CIA

| Dimension | Rules | Azure |
|---|---|---|
| confidentiality | High / High / High | Medium / Medium / Medium |
| integrity | Medium / Medium / Medium | Medium / Medium / Medium |
| availability | Medium / Medium / Medium | Medium / Medium / Medium |

## ISO27001

**5.15**: Access control

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/utils/auth.py:12` `def authorize(ensure_admin=False):` (Access control is insufficiently applied across handlers)

**5.17**: Authentication information

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/middlewares.py:20` `    storage = RedisStorage(app['redis'], httponly=False)` (Authentication information is exposed to client-side scripts and vulnerable to t)

**5.34**: Privacy and protection of PII

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/views.py:42` `            session['user_id'] = user.id` (PII stored in session and session cookie exposed to client-side scripts)

**8.2**: Privileged access rights

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/dao/user.py:12` `    username: str
    pwd_hash: str
    is_admin: bool` (Privileged/admin access rights present but not enforced)

**8.5**: Secure authentication

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `README.rst:132` `Rotate session identifiers on every single login and logout. Rotate session
identifiers on every user_id and/or permissi` (Multiple authentication weaknesses (session fixation, weak password hashing, coo)

**8.8**: Management of technical vulnerabilities

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `README.rst:15` `Python with as many vulnerabilities as possible while having a good design and` (No documented vulnerability management process in codebase)

**8.9**: Configuration management

- Rules: gap / gap / gap
  - `sqli/app.py:24` `debug=True,` (Debug mode enabled)
- Azure: not_evidenced / needs_review / needs_review
  - `sqli/app.py:18` `commandline.standard_argparse_options(ap, default_config='./config/dev.yaml')` (Configuration files and defaults are used but secure management of secrets is un)

**8.12**: Data leakage prevention

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/middlewares.py:69` `    response = render_template('errors/50x.jinja2',` (Potential leakage via error rendering and client-accessible session cookie)

**8.15**: Logging

- Rules: implemented / implemented / implemented
  - `run.py:8` `log = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: gap / gap / gap
  - `run.py:11` `    logging.basicConfig(level=logging.DEBUG)` (Logging configured at DEBUG level and limited control over sensitive output)

**8.20**: Networks security

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review / needs_review
  - `README.rst:33` `    docker-compose up` (Network exposure via docker-compose and HTTP; network segmentation not shown)

**8.24**: Use of cryptography

- Rules: gap / gap / gap
  - `sqli/dao/user.py:41` `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()` (Weak hash used for passwords or integrity)
- Azure: not_evidenced / gap / gap
  - `sqli/dao/user.py:1` `from hashlib import md5` (Insecure cryptographic use: MD5 for password hashing and templating autoescape d)

**8.25**: Secure development life cycle

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `README.rst:14` `The purpose of this project is to implement real-world like application in
Python with as many vulnerabilities as possib` (No explicit secure development lifecycle documented in repository)

**8.28**: Secure coding

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/dao/user.py:41` `        return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()` (Multiple insecure coding practices observed)


## ASVS

**V2.1.1**: User-set passwords are at least 12 characters long

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / gap
  - `sqli/views.py:38` `        password = data['password']` (No visible enforcement of minimum password length in application code)

**V2.4.1**: Passwords are stored using an approved, salted, adaptive hashing function

- Rules: gap / gap / gap
  - `sqli/dao/user.py:41` `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()` (Weak hash used for passwords or integrity)
- Azure: gap / gap / gap
  - `sqli/dao/user.py:1` `from hashlib import md5` (Passwords stored using MD5 (not an approved, salted, adaptive hash))

**V3.4.1**: Cookie-based session tokens have the Secure attribute set

- Rules: gap / gap / gap
  - `sqli/middlewares.py:20` `storage = RedisStorage(app['redis'], httponly=False)` (Session cookie without Secure/HttpOnly)
- Azure: gap / gap / needs_review
  - `sqli/middlewares.py:20` `    storage = RedisStorage(app['redis'], httponly=False)` (Session cookie Secure attribute not set when creating session storage)

**V3.4.2**: Cookie-based session tokens have the HttpOnly attribute set

- Rules: gap / gap / gap
  - `sqli/middlewares.py:20` `storage = RedisStorage(app['redis'], httponly=False)` (Session cookie without Secure/HttpOnly)
- Azure: gap / gap / gap
  - `sqli/middlewares.py:20` `    storage = RedisStorage(app['redis'], httponly=False)` (Session cookie HttpOnly attribute explicitly disabled)

**V4.1.1**: Access control rules are enforced on a trusted service layer

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/utils/auth.py:12` `def authorize(ensure_admin=False):` (Access control not consistently enforced at a service/trusted layer)

**V5.3.3**: Context-aware output escaping protects against reflected, stored and DOM-based XSS

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / needs_review
  - `sqli/views.py:121` `            review_text = data.get('review_text')` (Template output escaping not determinable from code snapshot)

**V5.3.4**: Database queries use parameterized queries, ORMs or are otherwise protected from injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `sqli/dao/student.py:43` `             "VALUES ('%(name)s')" % {'name': name})` (Some database queries use unsafe string interpolation or incorrect parameter usa)

**V5.3.8**: The application protects against OS command injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V5.5.3**: Deserialization of untrusted data is avoided or protected

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review / not_evidenced
  - `sqli/views.py:146` `            data = EVALUATE_SCHEMA.check_and_return(data)` (Deserialization of untrusted data)

**V6.2.2**: Industry-proven or government-approved cryptographic algorithms are used

- Rules: gap / gap / gap
  - `sqli/dao/user.py:41` `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()` (Weak hash used for passwords or integrity)
- Azure: not_evidenced / gap / gap
  - `sqli/dao/user.py:1` `from hashlib import md5` (Use of weak MD5 hashing for passwords)

**V6.4.1**: A secrets management solution is used to create, store and control access to secrets

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `config/dev.yaml:2` `  user: postgres
  password: postgres` (Secrets stored in plaintext configuration file instead of a secrets management s)

**V7.1.1**: The application does not log credentials or payment details

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / implemented
  - `sqli/views.py:36` `        data = await request.post()` (No explicit logging of credentials in application code, but global debug logging)

**V7.1.3**: The application logs security-relevant events

- Rules: implemented / implemented / implemented
  - `run.py:8` `log = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: implemented / implemented / implemented
  - `sqli/middlewares.py:34` `                'Request to %s was aborted because CSRF tokens mismatched',` (Security-relevant events are logged (CSRF failures))

**V9.2.1**: Connections use trusted TLS certificates that are validated

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / gap / gap
  - `README.rst:35` `Then visit http://localhost:8080 in your favorite browser.` (Application served over plain HTTP by default)

**V12.3.1**: User-submitted filename metadata is not used directly by filesystems (path traversal)

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V14.3.2**: Web or application server and framework debug modes are disabled in production

- Rules: gap / gap / gap
  - `sqli/app.py:24` `debug=True,` (Debug mode enabled)
- Azure: not_evidenced / gap / gap
  - `sqli/app.py:23` `app = Application(
        debug=True,` (Debug mode enabled in application and logging at DEBUG level)

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
