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
