# Labelling worksheet: fastapi-template

Source: `https://github.com/fastapi/full-stack-fastapi-template.git` at `aabb90126964a164e02aff39e7c385bb0598236d`

Use this to find where to look, then decide from the code yourself. The tools are often wrong.

Each cell lists one status per run (rules: 3 runs, Azure: 3 runs).

## CIA

| Dimension | Rules | Azure |
|---|---|---|
| confidentiality | High / High / High | Medium / Medium / Medium |
| integrity | High / High / High | Medium / High / Medium |
| availability | Medium / Medium / Medium | Medium / Low / Medium |

## ISO27001

**5.15**: Access control

- Rules: implemented / implemented / implemented
  - `backend/app/api/deps.py:49` `CurrentUser = Annotated[User, Depends(get_current_user)]` (Server-side access control checks)
- Azure: implemented / implemented / implemented
  - `backend/app/api/routes/users.py:34` `    dependencies=[Depends(get_current_active_superuser)],` (Access control checks present)

**5.17**: Authentication information

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / implemented
  - `backend/app/api/routes/login.py:37` `    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_toke` (Handling of authentication information (tokens, secrets))

**5.34**: Privacy and protection of PII

- Rules: needs_review / needs_review / needs_review
  - `backend/app/api/routes/login.py:31` `session=session, email=form_data.username, password=form_data.password` (Personal data processed)
- Azure: gap / gap / gap
  - `backend/app/utils.py:97` `"password": password,` (Credentials included in outbound email content (PII exposure))

**8.2**: Privileged access rights

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `backend/app/api/routes/users.py:214` `@router.delete("/{user_id}", dependencies=[Depends(get_current_active_superuser)])` (Privileged access restrictions)

**8.5**: Secure authentication

- Rules: implemented / implemented / implemented
  - `backend/app/core/security.py:6` `from pwdlib.hashers.argon2 import Argon2Hasher` (Adaptive password hashing in use)
- Azure: implemented / implemented / implemented
  - `backend/app/crud.py:42` `DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$MjQyZWE1MzBjYjJlZTI0Yw$YTU4NGM5ZTZmYjE2NzZlZjY0ZWY3ZGRkY2U2OWFjNjk"` (Authentication mechanisms and token expiry)

**8.8**: Management of technical vulnerabilities

- Rules: implemented / implemented / implemented
  - `.github/workflows/guard-dependencies.yml:27` `const botAllowlist = new Set(['dependabot[bot]']);` (Dependency or security scanning in CI)
- Azure: implemented / implemented / implemented
  - `.github/workflows/guard-dependencies.yml:3` `on:
  pull_request_target: # zizmor: ignore[dangerous-triggers] -- This workflow only reads context.payload metadata, ne` (Automated dependency and security tooling present)

**8.9**: Configuration management

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `.github/workflows/deploy-docker-compose.yml:20` `    env:
      DOMAIN: ${{ vars.DOMAIN }}
      PROJECT_NAME: ${{ vars.PROJECT_NAME }}
      SECRET_KEY: ${{ secrets.SEC` (Secrets and configuration passed via environment variables and GitHub secrets in)

**8.12**: Data leakage prevention

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `backend/app/utils.py:97` `"password": password,` (Potential data leakage via emails containing passwords)

**8.15**: Logging

- Rules: implemented / implemented / implemented
  - `backend/app/initial_data.py:8` `logger = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: needs_review / gap / needs_review
  - `backend/app/utils.py:15` `logging.basicConfig(level=logging.INFO)` (Application logging configuration and sensitive data handling)

**8.20**: Networks security

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `compose.override.yml:5` `    ports:
      - "80:80"
      - "8090:8080"` (Insecure Traefik dashboard/API enabled in override compose file)

**8.24**: Use of cryptography

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / needs_review
  - `backend/app/utils.py:110` `    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email},
        settings.SECRET_KEY,
        algor` (Cryptography used for JWTs but broader cryptographic usage not fully visible)

**8.25**: Secure development life cycle

- Rules: implemented / implemented / implemented
  - `.github/workflows/guard-dependencies.yml:27` `const botAllowlist = new Set(['dependabot[bot]']);` (Dependency or security scanning in CI)
- Azure: implemented / implemented / implemented
  - `.github/workflows/pre-commit.yml:56` `      - name: Install backend dependencies
        run: uv sync --all-packages
      - name: Install frontend dependenci` (Security tooling and developer hygiene automation present)

**8.28**: Secure coding

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / implemented / implemented
  - `backend/app/crud.py:40` `# Dummy hash to use for timing attack prevention when user is not found` (General secure coding practices)


## ASVS

**V2.1.1**: User-set passwords are at least 12 characters long

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: gap / gap / gap
  - `frontend/src/routes/reset-password.tsx:37` `      .min(8, { message: "Password must be at least 8 characters" }),` (Password minimum length enforcement)

**V2.4.1**: Passwords are stored using an approved, salted, adaptive hashing function

- Rules: implemented / implemented / implemented
  - `backend/app/core/security.py:6` `from pwdlib.hashers.argon2 import Argon2Hasher` (Adaptive password hashing in use)
- Azure: implemented / implemented / implemented
  - `backend/app/crud.py:11` `    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password` (Adaptive password hashing in use)

**V3.4.1**: Cookie-based session tokens have the Secure attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V3.4.2**: Cookie-based session tokens have the HttpOnly attribute set

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V4.1.1**: Access control rules are enforced on a trusted service layer

- Rules: implemented / implemented / implemented
  - `backend/app/api/deps.py:49` `CurrentUser = Annotated[User, Depends(get_current_user)]` (Server-side access control checks)
- Azure: implemented / implemented / implemented
  - `backend/app/api/routes/users.py:32` `    "/",
    dependencies=[Depends(get_current_active_superuser)],
    response_model=UsersPublic,` (Access control enforced in API layer)

**V5.3.3**: Context-aware output escaping protects against reflected, stored and DOM-based XSS

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / needs_review
  - `backend/app/api/routes/items.py:44` `items_public = [ItemPublic.model_validate(item) for item in items]` (Context-aware output escaping for XSS)

**V5.3.4**: Database queries use parameterized queries, ORMs or are otherwise protected from injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `backend/app/crud.py:35` `statement = select(User).where(User.email == email)` (Use of ORM/parameterized queries)

**V5.3.8**: The application protects against OS command injection

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V5.5.3**: Deserialization of untrusted data is avoided or protected

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `backend/app/crud.py:11` `db_obj = User.model_validate(` (Safe deserialization practices)

**V6.2.2**: Industry-proven or government-approved cryptographic algorithms are used

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / needs_review
  - `backend/app/utils.py:110` `    encoded_jwt = jwt.encode(
        {"exp": exp, "nbf": now, "sub": email},
        settings.SECRET_KEY,
        algor` (Cryptographic algorithm selection for JWTs not verifiable from code snapshot)

**V6.4.1**: A secrets management solution is used to create, store and control access to secrets

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `release-notes.md:96` ` * ♻️ Require explicit SECRET_KEY. PR [#2425](https://github.com/fastapi/full-stack-fastapi-template/pull/2425) by [@tia` (A secrets management solution is used to create, store and control access to sec)

**V7.1.1**: The application does not log credentials or payment details

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `backend/app/utils.py:15` `logging.basicConfig(level=logging.INFO)` (No direct logging of credentials found)

**V7.1.3**: The application logs security-relevant events

- Rules: implemented / implemented / implemented
  - `backend/app/initial_data.py:8` `logger = logging.getLogger(__name__)` (Security-relevant logging present)
- Azure: gap / gap / gap
  - `backend/app/api/routes/login.py:23` `@router.post("/login/access-token")` (Lack of logging for authentication and password events)

**V9.2.1**: Connections use trusted TLS certificates that are validated

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / gap / gap
  - `compose.deploy.yml:26` `- --certificatesresolvers.le.acme.storage=/certificates/acme.json` (Traefik configured for Let's Encrypt but an insecure API/dashboard mode is prese)

**V12.3.1**: User-submitted filename metadata is not used directly by filesystems (path traversal)

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / not_evidenced

**V14.3.2**: Web or application server and framework debug modes are disabled in production

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / gap / implemented
  - `backend/app/main.py:18` `if settings.SENTRY_DSN and settings.FASTAPI_ENV != "development":` (Debug/dev modes are gated by FASTAPI_ENV but production disable cannot be fully )

**V14.5.3**: The CORS Access-Control-Allow-Origin header uses a strict allow list

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: implemented / implemented / implemented
  - `backend/app/main.py:27` `app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_HOST],
    allow_credentials=True,
    allo` (CORS configured to allow a single frontend host)


## NIST_AI_RMF

**GOVERN 1.1**: Legal and regulatory requirements involving AI are understood, managed and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `CONTRIBUTING.md:34` `You are encouraged to use all the tools you want to do your work and contribute as efficiently as possible, this include` (No explicit legal/regulatory AI compliance documentation found in snapshot)

**MAP 1.1**: Intended purposes, context and expected use of the AI system are understood and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / needs_review / needs_review
  - `CONTRIBUTING.md:32` `## Automated Code and AI` (Limited documentation on acceptable use of AI tools for contributions)

**MEASURE 2.7**: AI system security and resilience are evaluated and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `CONTRIBUTING.md:16` `Note that PRs from non-team members are not allowed to modify 'pyproject.toml' or 'uv.lock', to prevent supply chain ris` (Limited security-related guidance present; no AI-specific security/resilience ev)

**MEASURE 2.10**: Privacy risk of the AI system is examined and documented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: not_evidenced / not_evidenced / needs_review
  - `CONTRIBUTING.md:62` `Avoid inadvertently doing harm.` (No explicit privacy risk assessment for AI components in the inspected files)

**MANAGE 4.1**: Post-deployment monitoring plans for the AI system are implemented

- Rules: not_evidenced / not_evidenced / not_evidenced
- Azure: needs_review / not_evidenced / needs_review
  - `CONTRIBUTING.md:40` `### Closing Automated and AI PRs` (Some operational references but no explicit post-deployment AI monitoring plan)
