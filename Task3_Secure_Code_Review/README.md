# Task 3: Secure Coding Review
## OWASP Juice Shop: Black-Box Testing and Source Code Review

**Program:** CodeAlpha Cyber Security Internship
**Task:** 3: Secure Coding Review
**Reviewer:** Muhammad Rizik Sudrajat
**Date:** 1 November 2026
**Target:** OWASP Juice Shop (local instance, intentionally vulnerable application)
**Language / framework:** TypeScript, Node.js, Express, Sequelize
**Method:** Black-box testing, then manual source code review mapped to OWASP and CWE

---

## 1. Disclaimer

OWASP Juice Shop is a training application built by OWASP to contain known vulnerabilities. All testing was performed on a locally hosted instance. No real systems, third-party services, or production data were accessed. The flaws described below are intentional in Juice Shop, but in a real product each one would be a reportable vulnerability.

## 2. Executive Summary

The review identified **4 security findings**: 1 Critical and 3 High. The most serious is SQL injection in the login handler, which allows authentication bypass without credentials. A Broken Object Level Authorization flaw in the basket API lets any logged-in user read other users' baskets; this was confirmed both by black-box testing and by reading the source. Two cryptographic weaknesses (unsalted MD5 password hashing and hardcoded signing keys) increase the damage of any data leak.

## 3. Scope and Methodology

| Item | Detail |
|---|---|
| Application | OWASP Juice Shop, local instance |
| Source files reviewed | `routes/basket.ts`, `routes/login.ts`, `lib/insecurity.ts` |
| Black-box tools | Firefox DevTools (Network tab), cURL |
| Code review | Manual inspection of server-side TypeScript |
| Classification | OWASP Top 10 (2021), OWASP API Security Top 10 (2023), CWE, CVSS 3.1 |

**Approach:** (1) capture a real request, (2) test the authentication and authorization boundary, (3) locate the handler in the source, (4) explain why the behaviour occurs, (5) propose a fix.

## 4. Summary of Findings

| ID | Finding | Severity | CWE | OWASP |
|---|---|---|---|---|
| F-01 | Broken Object Level Authorization (IDOR) in basket API | **High** (7.1) | CWE-639 / CWE-862 | API1:2023 |
| F-02 | SQL injection in login | **Critical** (9.8) | CWE-89 | A03:2021 Injection |
| F-03 | Weak password hashing (unsalted MD5) | **High** | CWE-328 / CWE-916 | A02:2021 Cryptographic Failures |
| F-04 | Hardcoded cryptographic secrets | **High** | CWE-798 / CWE-321 | A02:2021 Cryptographic Failures |

## 5. Detailed Findings

### F-01: Broken Object Level Authorization in the basket API

| Field | Value |
|---|---|
| Location | `routes/basket.ts`, `retrieveBasket()` |
| Endpoint | `GET /rest/basket/{id}` |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 7.1 |

**Black-box evidence**

1. The request that loads the basket was captured in DevTools: `GET /rest/basket/6`.
2. Without any Authorization header the server rejects the request:

```bash
curl -s 'http://localhost:3000/rest/basket/6'
```

```json
{ "error": { "message": "No Authorization header was found", "name": "UnauthorizedError", "code": "credentials_required", "status": 401 } }
```

Authentication is enforced.

3. With a valid token for basket 6, the ID in the URL was changed to 1 (a different user's basket):

```bash
curl -s 'http://localhost:3000/rest/basket/1' -H 'Authorization: Bearer [REDACTED_JWT]'
```

```json
{ "status": "success", "data": { "id": 1, "UserId": 1, "Products": [ "..." ] } }
```

The server returned another user's basket (`UserId: 1`).

**Source code analysis**

The handler takes the ID from the URL and uses it directly in the database query:

```ts
const id = req.params.id
BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, ... }] })
```

The query is not restricted to the logged-in user. The code does compare the requested ID with the user's own basket (`user.bid != id`), but only inside `challengeUtils.solveIf(...)`. That call detects the attack so the training challenge can be marked solved; it does not block the response, and the basket is still returned with `res.json(...)`. The route middleware (`security.isAuthorized()`) only checks that a valid token exists, which is authentication, not authorization.

**Impact:** Any authenticated user can enumerate basket IDs (`/1`, `/2`, `/3`, ...) and read every other user's basket. The same pattern could expose other endpoints that trust an ID from the client.

**Fix**

```ts
const user = security.authenticatedUsers.from(req)
if (!user || String(user.bid) !== String(id)) {
  return res.status(403).json({ error: 'Forbidden' })
}
```

Better still, query by both ID and owner (`where: { id, UserId: <authenticated user id> }`) so a foreign basket is never loaded, and return 404 when nothing matches. Use non-guessable identifiers for user-owned resources and add regression tests asserting that user A cannot read user B's basket.

**Remediation verification (separate demo app)**

To check that the ownership rule works, it was implemented in a small standalone demo API (not part of Juice Shop) with a vulnerable and a secure endpoint, and both were tested with a token issued for user 26.

| Request | Result | Meaning |
|---|---|---|
| `GET /vulnerable/basket/1` | Returns basket of user 1 | IDOR reproduced |
| `GET /secure/basket/1` | `{"error":"Not found"}` | Foreign basket rejected (fail closed) |
| `GET /secure/basket/6` | Returns basket of user 26 | Legitimate access still works |

---

### F-02: SQL injection in login

| Field | Value |
|---|---|
| Location | `routes/login.ts` |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 |

**Issue:** The login query is built by inserting the request body directly into the SQL string:

```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)
```

**Impact:** The attacker controls the structure of the query, so authentication can be bypassed and data can be read from the database. No account is required.

**Fix:** Use bound parameters instead of string building:

```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email || '', password: hashedPassword }, model: models.User, plain: true }
)
```

Also validate the email format and return one generic error message for failed logins.

---

### F-03: Weak password hashing

| Field | Value |
|---|---|
| Location | `lib/insecurity.ts`, `hash()` |

**Issue:** Passwords are hashed with `crypto.createHash('md5')`. MD5 is fast and unsalted here, so identical passwords produce identical hashes and cracking with lookup tables or GPUs is easy.

**Impact:** If the database or a token containing the hash leaks, passwords can be recovered quickly.

**Fix:** Use a slow, salted algorithm such as Argon2id or bcrypt. Look up the user by email, then verify with `argon2.verify` or `bcrypt.compare` in code, and migrate old hashes at next login.

---

### F-04: Hardcoded cryptographic secrets

| Field | Value |
|---|---|
| Location | `lib/insecurity.ts` |

**Issue:** The RSA private key used to sign JWTs and the HMAC secret are written as string literals in the source code.

**Impact:** Anyone with access to the repository can forge valid session tokens, and the keys cannot be rotated without changing the code.

**Fix:** Load keys from environment variables or a secrets manager, keep them out of version control, rotate the exposed keys, and add secret scanning (for example gitleaks) to CI.

## 6. Remediation Priority

| Priority | Finding | Reason |
|---|---|---|
| 1 | F-02 SQL injection | Unauthenticated, full compromise of the data |
| 2 | F-01 Broken object-level authorization | Any user can read other users' data |
| 3 | F-04 Hardcoded secrets | Allows forging of sessions |
| 4 | F-03 MD5 hashing | Amplifies the damage of a data leak |

## 7. Secure Coding Recommendations

1. Authentication is not authorization: check object ownership on every request that takes an ID.
2. Never trust identifiers from the URL, request body, or client-side storage.
3. Put authorization checks in the code path that returns data, not only in logging or monitoring logic.
4. Use parameterized queries or an ORM; never build SQL with string concatenation.
5. Hash passwords with Argon2id or bcrypt; never MD5 or SHA-1.
6. Keep secrets out of source control and rotate them if exposed.
7. Return 403 or 404 when ownership fails (fail closed) and generic errors for failed logins.
8. Add automated tests for cross-user access and run static analysis and secret scanning in CI.

## 8. Conclusion

The review shows how small coding mistakes lead to serious vulnerabilities. The basket endpoint authenticates users but never authorizes access to the specific object; reading the source confirmed that the ownership comparison exists only to detect the attack, not to block it. Combined with injectable SQL, weak hashing, and hardcoded keys, these issues show why input handling, authorization, and key management must be designed in from the start. Every finding has a well-known fix.

---

**Tools used:** Firefox DevTools, cURL, manual source code review
**References:** OWASP Top 10 (2021), OWASP API Security Top 10 (2023), CWE, OWASP Juice Shop source code
