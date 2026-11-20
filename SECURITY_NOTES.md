# Security baseline, 2026-11-05

Tested against the cloned recipe-box-api skeleton running locally on
127.0.0.1:5000. Every request below was sent with no auth header, no token
and no cookie.

## What an anonymous requester can do

- `GET /recipes` returns every recipe, including id 3 which has
  `is_public: false`. The field is stored but nothing reads it.
- `PATCH /recipes/1` changed the title and returned `200 OK`. A follow up
  `GET /recipes` confirmed the change persisted.
- `DELETE /recipes/2` returned `204 NO CONTENT` and the recipe was gone from
  the next `GET /recipes`.

Anonymous can read, change, and delete with no identity supplied.

## Information the API gives away

- `PUT /recipes/1` is not a route, and the `405 METHOD NOT ALLOWED` response
  includes `Allow: PATCH, DELETE, GET, OPTIONS, HEAD`. An anonymous caller
  learns which methods are enabled, including `DELETE`, just by guessing wrong.

## The underlying problem

The API returns valid JSON and correct status codes. Nothing is broken in the
HTTP sense: `200` and `204` are the right answers to the questions being asked.

The problem is that the API never asks who is making the request, so there is
no basis on which to refuse one. Because no identity arrives with the request,
there is also nothing meaningful to log. After the fact there is no way to
find out who deleted recipe 2.

## Notes for later changes (not implemented yet)

- Requests will need to carry some form of identity.
- Write operations will need to check that identity before acting.
- `is_public` will need to be enforced on read, not just stored.

## Admin scope, decided 2026-11-20

Admins bypass ownership on writes (PATCH, DELETE) but get no special read
access. An admin cannot read a private recipe they are able to delete.

This is deliberate. Moderation needs the power to remove content, not the
power to read everyone's private data. A universal read bypass would turn
every admin account into a surveillance tool over user content, and a stolen
admin token would then leak every private recipe in the system rather than
just allowing destructive actions that are at least visible after the fact.

Found during the Unit 3 pen test, where admin GET on a private recipe
returned 404 while admin DELETE on the same recipe returned 204. The
inconsistency was originally an accident: the bypass lives in
require_recipe_access, which only guards writes. Keeping it.

Verified behaviour:
- anonymous write        401
- authenticated non-owner 403
- owner / admin write     200 or 204
- unowned recipe, user    403
- unowned recipe, admin   200
- private read, anyone but owner  404
- alg=none forgery        401
- token signed with wrong secret  401
- valid token with role edited to admin  401

## End-to-end security audit, 2026-11-20

Audited the recipe API against the course threat model. Every result below
was verified at the database, not by status code alone.

**Password storage.** All users store `password_hash`, pbkdf2:sha256, 103
chars, per-user salt. No plaintext. pbkdf2 is pinned over Werkzeug's scrypt
default for portability (LibreSSL builds lack scrypt); a deliberate decision,
not a downgrade.

**Authentication.** Write routes reject no token, forged token, wrong-secret
token, and expired token, all 401, data unchanged. Verified with a
row-diff harness that also confirmed a valid owner edit does change the row,
proving the harness can detect a change.

**Ownership.** On PATCH and DELETE: non-owner 403 row intact, owner and admin
succeed. A refused delete was re-attempted and the row was still present.

**Reads.** Anonymous GET /recipes returns only public recipes; the private
seeded recipe does not leak. Private single-GET returns 404 to non-owners,
byte-identical to a genuine 404.

**Regression.** The two Unit 2 Lesson 1 attacks (anonymous PATCH and DELETE)
now return 401 with no data change. The anonymous list no longer leaks the
private recipe.

**Verdict.** Clean for this course's single-service threat model:
authentication, authorization, ownership and role all enforced and proven.

**Known scars and accepted limitations.**
- Recipe 1 is still titled "Shakshuka (edited by anonymous)", real damage
  from the pre-auth window. Left in place as evidence; hardening prevents
  recurrence but cannot undo prior damage.
- Admins bypass ownership on writes only, not reads (documented above).
- Out of scope, as a single service: TLS, rate limiting and brute-force
  defense, secret/key management, OAuth/SSO, and secure account recovery.
