# Labelling worksheet: juice-shop

Source: `https://github.com/juice-shop/juice-shop.git` at `717f5efa886b0417eeecb52378b03cf10567b7e2`

Use this to find where to look, then decide from the code yourself. The tools are often wrong.

Each cell lists one status per run (rules: 3 runs, Azure: 3 runs).

## CIA

| Dimension | Rules | Azure |
|---|---|---|
| confidentiality | High / High / High | High / High / High |
| integrity | High / High / High | High / High / High |
| availability | Medium / Medium / Medium | Medium / Low / Medium |

## ISO27001

**5.15**: Access control

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `frontend/src/app/app.routing.ts:79` `    component: AdministrationComponent, // vuln-code-snippet neutral-line adminSectionChallenge
    canActivate: [AdminG` (Access control implemented client-side only in visible code)

**5.17**: Authentication information

- Rules: gap / gap / gap
  - `data/static/users.yml:3` `password: '[REDACTED:credential]'` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `frontend/src/app/app.guard.spec.ts:32` `        localStorage.setItem('token', 'TOKEN')` (Authentication tokens stored in client-side storage and UI allows 'remember me')

**5.34**: Privacy and protection of PII

- Rules: needs_review / needs_review / needs_review
  - `data/static/users.yml:2` `email: admin` (Personal data processed)
- Azure: gap / gap / gap
  - `data/static/users.yml:6` `    securityQuestion:
    id: 2
    answer: '@xI98PxDO+06!'` (PII present in repository in cleartext)

**8.2**: Privileged access rights

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / gap
  - `data/static/users.yml:171` `  role: 'admin'
  isAdmin: true` (Privileged roles and isAdmin flag present — server-side enforcement and provisio)

**8.5**: Secure authentication

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `frontend/src/app/forgot-password/forgot-password.component.spec.ts:116` `    it('should have a password length of at least five characters', () => {` (Multiple insecure authentication practices visible)

**8.8**: Management of technical vulnerabilities

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `SECURITY.md:11` `We provide security patches for the latest released minor version.` (Security policy and vulnerability reporting present)

**8.9**: Configuration management

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / gap / gap
  - `config/default.yml:52` `  securityTxt:
    contact: 'mailto:donotreply@owasp-juice.shop'
    encryption: 'https://keybase.io/bkimminich/pgp_keys` (Configuration files and usage present)

**8.12**: Data leakage prevention

- Rules: gap / gap / gap
  - `routes/chat.ts:255` `logger.warn('Failed to record chat token usage metrics: ' + summarizeLlmError(metricError))` (Credentials written to logs)
- Azure: gap / gap / gap
  - `frontend/src/app/payment-method/payment-method.component.spec.ts:110` `        console.log = vi.fn()` (Uncontrolled console logging and storage of identifiers may leak data)

**8.15**: Logging

- Rules: implemented / implemented / implemented
  - `lib/startup/validateConfig.ts:42` `logger.info('Configuration ${colors.bold(process.env.NODE_ENV ?? 'default')} validated (${colors.green('SUCCESS')})')` (Security-relevant logging present)
- Azure: gap / gap / needs_review
  - `routes/payment.ts:31` `      const cardNumber = String(card.cardNum)` (Ad-hoc console logging and raw sensitive data in repo indicate inadequate loggin)

**8.20**: Networks security

- Rules: gap / gap / gap
  - `server.ts:183` `app.options('*', cors())` (CORS allows any origin)
- Azure: gap / gap / gap
  - `server.ts:183` `  app.options('*', cors())
  app.use(cors())` (Network-related exposures: permissive CORS and directory browsing enabled)

**8.24**: Use of cryptography

- Rules: gap / gap / gap
  - `data/static/users.yml:3` `password: '[REDACTED:credential]'` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `lib/insecurity.ts:20` `export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'` (Insecure or improperly managed cryptographic usage)

**8.25**: Secure development life cycle

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / needs_review / implemented
  - `SECURITY.md:1` `# Security Policy

OWASP Juice Shop is an _intentionally vulnerable_ web application, but we still do not want to be sup` (Security policy and CI present supporting a development lifecycle)

**8.28**: Secure coding

- Rules: gap / gap / gap
  - `data/static/codefixes/dbSchemaChallenge_1.ts:5` `models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') ` (SQL query built from strings)
- Azure: gap / gap / gap
  - `routes/login.ts:34` `models.sequelize.query('SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.` (Multiple insecure coding patterns present (SQL injection, unsanitized inputs, ra)


## ASVS

**V2.1.1**: User-set passwords are at least 12 characters long

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `frontend/src/app/change-password/change-password.component.html:59` `            'INVALID_PASSWORD_LENGTH' | translate: { length: '5-40' }` (Password minimum length is weaker than 12 characters)

**V2.4.1**: Passwords are stored using an approved, salted, adaptive hashing function

- Rules: gap / gap / gap
  - `lib/insecurity.ts:41` `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')` (Weak hash used for passwords or integrity)
- Azure: gap / gap / gap
  - `data/static/users.yml:132` `  password: 'Mr. N00dles'` (Passwords present in static data in plaintext (no evidence of salted adaptive ha)

**V3.4.1**: Cookie-based session tokens have the Secure attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review / not_evidenced
  - `frontend/src/app/app.guard.spec.ts:32` `        localStorage.setItem('token', 'TOKEN')` (Session cookies set Secure attribute)

**V3.4.2**: Cookie-based session tokens have the HttpOnly attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / needs_review / not_evidenced
  - `frontend/src/app/app.guard.spec.ts:32` `        localStorage.setItem('token', 'TOKEN')` (Session cookies set HttpOnly attribute)

**V4.1.1**: Access control rules are enforced on a trusted service layer

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `frontend/src/app/app.routing.ts:79` `    component: AdministrationComponent, // vuln-code-snippet neutral-line adminSectionChallenge
    canActivate: [AdminG` (Access control enforced in client-side guards only (not a trusted service layer))

**V5.3.3**: Context-aware output escaping protects against reflected, stored and DOM-based XSS

- Rules: gap / gap / gap
  - `frontend/src/app/about/about.component.ts:120` `feedbacks[i].comment = this.sanitizer.bypassSecurityTrustHtml(` (Output rendered without escaping)
- Azure: gap / gap / gap
  - `routes/createProductReviews.ts:23` `await reviewsCollection.insert({` (Lack of context-aware output escaping for user-supplied content)

**V5.3.4**: Database queries use parameterized queries, ORMs or are otherwise protected from injection

- Rules: gap / gap / gap
  - `data/static/codefixes/dbSchemaChallenge_1.ts:5` `models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') ` (SQL query built from strings)
- Azure: gap / gap / gap
  - `routes/login.ts:34` `models.sequelize.query('SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.` (Direct concatenation into SQL query (SQL injection risk))

**V5.3.8**: The application protects against OS command injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V5.5.3**: Deserialization of untrusted data is avoided or protected

- Rules: gap / gap / gap
  - `lib/scripts/lintConfig.ts:22` `configuration = yaml.load(await readFile(file, 'utf8'))` (Unsafe deserialisation or eval)
- Azure: needs_review / needs_review / implemented
  - `server.ts:344` `// @ts-expect-error FIXME intentionally saving original request in this property` (Unrestricted JSON deserialization present; custom parsing used in places)

**V6.2.2**: Industry-proven or government-approved cryptographic algorithms are used

- Rules: gap / gap / gap
  - `lib/insecurity.ts:41` `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')` (Weak hash used for passwords or integrity)
- Azure: gap / gap / gap
  - `lib/insecurity.ts:41` `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')` (Use of weak or deprecated cryptographic primitives)

**V6.4.1**: A secrets management solution is used to create, store and control access to secrets

- Rules: gap / gap / gap
  - `data/static/users.yml:3` `password: '[REDACTED:credential]'` (Hard-coded secret in source)
- Azure: gap / gap / gap
  - `data/static/users.yml:151` `  totpSecret: IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH` (Secrets and sensitive keys present in repository data instead of a secrets manag)

**V7.1.1**: The application does not log credentials or payment details

- Rules: gap / gap / gap
  - `routes/chat.ts:255` `logger.warn('Failed to record chat token usage metrics: ' + summarizeLlmError(metricError))` (Credentials written to logs)
- Azure: gap / gap / gap
  - `data/static/users.yml:22` `      cardNum: 4716190207394368` (Avoid logging or storing credentials/payment details in plaintext)

**V7.1.3**: The application logs security-relevant events

- Rules: implemented / implemented / implemented
  - `lib/startup/validateConfig.ts:42` `logger.info('Configuration ${colors.bold(process.env.NODE_ENV ?? 'default')} validated (${colors.green('SUCCESS')})')` (Security-relevant logging present)
- Azure: needs_review / implemented / needs_review
  - `frontend/src/app/address/address.component.spec.ts:111` `        console.log = vi.fn()` (Logging of security-relevant events via console is present but coverage/controls)

**V9.2.1**: Connections use trusted TLS certificates that are validated

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / needs_review
  - `threat-model.json:281` `              "isPublicNetwork": true,` (TLS certificate validation not observable in provided code snapshot)

**V12.3.1**: User-submitted filename metadata is not used directly by filesystems (path traversal)

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / needs_review / implemented
  - `server.ts:276` `if (filePath.endsWith('.tf') || filePath.endsWith('.yml') || filePath.endsWith('Dockerfile')) {` (Filesystem reads use file paths without evident sanitization)

**V14.3.2**: Web or application server and framework debug modes are disabled in production

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / needs_review
  - `server.ts:298` `  app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' }))` (No explicit evidence that debug modes are disabled in production)

**V14.5.3**: The CORS Access-Control-Allow-Origin header uses a strict allow list

- Rules: gap / gap / gap
  - `server.ts:183` `app.options('*', cors())` (CORS allows any origin)
- Azure: gap / gap / gap
  - `server.ts:183` `  app.options('*', cors())` (Permissive CORS configuration (allows all origins))


## NIST_AI_RMF

**GOVERN 1.1**: Legal and regulatory requirements involving AI are understood, managed and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**MAP 1.1**: Intended purposes, context and expected use of the AI system are understood and documented

- Rules: needs_review / needs_review / needs_review
  - `package.json:94` `"@ai-sdk/openai-compatible": "^2.0.35",` (AI / LLM component present)
- Azure: implemented / implemented / implemented
  - `routes/chat.ts:84` `  return 'You are "${botName}", the friendly customer service chatbot of the ${appName} online store.` (AI chat system purpose and behavior documented in system prompt and configuratio)

**MEASURE 2.7**: AI system security and resilience are evaluated and documented

- Rules: needs_review / needs_review / needs_review
  - `package.json:94` `"@ai-sdk/openai-compatible": "^2.0.35",` (AI / LLM component present)
- Azure: needs_review / needs_review / needs_review
  - `config/default.yml:22` `    llmApiUrl: 'http://localhost:11434/v1'` (Resilience controls (retries, error handling) present but no documented security)

**MEASURE 2.10**: Privacy risk of the AI system is examined and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / needs_review
  - `routes/chat.ts:83` `  const userIdentifier = userName ? '\nThe customer you are currently chatting with is ${userName}.' : ''` (User-identifying data and internal/confidential instructions are included in pro)

**MANAGE 4.1**: Post-deployment monitoring plans for the AI system are implemented

- Rules: needs_review / needs_review / needs_review
  - `package.json:94` `"@ai-sdk/openai-compatible": "^2.0.35",` (AI / LLM component present)
- Azure: needs_review / needs_review / needs_review
  - `routes/chat.ts:267` `      logger.warn('Chatbot connection error: ' + summarizeLlmError(error))` (Operational logging and SSE error handling present but no clear monitoring plan )
