"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request

from auth_utils import (create_access_token, decode_access_token,
                        hash_password, verify_password)

DATABASE = "recipes.db"

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def require_auth(view):
    """Reject the request unless it carries a valid Bearer token."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(
                {"error": "missing or invalid Authorization header"}
            ), 401
        token = header[len("Bearer "):].strip()
        if not token:
            return jsonify(
                {"error": "missing or invalid Authorization header"}
            ), 401
        try:
            claims = decode_access_token(token)
        except jwt.PyJWTError:
            return jsonify({"error": "invalid or expired token"}), 401
        g.current_user_id = int(claims["sub"])
        g.current_username = claims.get("username")
        return view(*args, **kwargs)
    return wrapper


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
@require_auth
def create_recipe():
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public)"
            " VALUES (?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204


def user_to_dict(row):
    """Serialize a user row. Never includes password_hash."""
    return {
        "id": row["id"],
        "email": row["email"],
        "username": row["username"],
        "created_at": row["created_at"],
    }


@app.post("/register")
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    for name in ("email", "username", "password"):
        value = data.get(name)
        if not isinstance(value, str) or not value.strip():
            return jsonify(
                {"error": "email, username and password are required"}
            ), 400
    email = data["email"].strip()
    username = data["username"].strip()
    password = data["password"]
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (email, username, password_hash)"
            " VALUES (?, ?, ?)",
            (email, username, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(
            {"error": "account with those details already exists"}
        ), 409
    row = db.execute(
        "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(user_to_dict(row)), 201


# Burned through whenever no user matches, so that a missing account and
# a wrong password cost the same wall-clock time. Without this, the fast
# path leaks which usernames exist even though the response is identical.
_DUMMY_HASH = hash_password("timing-parity-placeholder")


@app.post("/login")
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    identifier = data.get("username") or data.get("email")
    password = data.get("password")
    if not isinstance(identifier, str) or not identifier.strip():
        return jsonify({"error": "credentials are required"}), 400
    if not isinstance(password, str) or not password:
        return jsonify({"error": "credentials are required"}), 400
    identifier = identifier.strip()
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (identifier, identifier),
    ).fetchone()
    stored_hash = row["password_hash"] if row is not None else _DUMMY_HASH
    matched = verify_password(stored_hash, password)
    if row is None or not matched:
        return jsonify({"error": "invalid credentials"}), 401
    token = create_access_token(row["id"], row["username"])
    return jsonify({
        "id": row["id"],
        "username": row["username"],
        "access_token": token,
        "token_type": "Bearer",
    })


if __name__ == "__main__":
    app.run(debug=True)
