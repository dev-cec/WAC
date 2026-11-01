"""make-web-databases.py — the web applications' witness databases (B-035,
lot 2), made on the host so that their accounts are known here and nowhere
else: wac-app.db (a WordPress-like wp_users, phpass and bcrypt hashes), put
by place-file-artefacts.ps1 in the site's App_Data, and wac-outside.db (an
ASP.NET Core Identity AspNetUsers, an Identity v3 hash), put outside the
site, in C:\\wacdata. Each account is written to the reference as
"account=<database on the VM>|<login column>|<login>|<hash>", which
check-json.py confronts with web_server_accounts.json.

Usage: make-web-databases.py <folder> <reference file>
"""
import os
import sqlite3
import sys

# The database on the VM: its file here, its table, its rows, the login and hash columns.
DATABASES = {
    "C:\\inetpub\\wwwroot\\App_Data\\wac-app.db": (
        "wac-app.db",
        "CREATE TABLE wp_users(ID INTEGER PRIMARY KEY, user_login TEXT, user_pass TEXT, user_registered TEXT)",
        "INSERT INTO wp_users VALUES(?, ?, ?, ?)",
        [(1, "wacadmin", "$P$BwacWitnessPhpassHash000000000.", "2026-11-01 10:00:00"),
         (2, "wacintruder", "$2y$10$wacWitnessBcryptHash00000uJ1Xb0fYfXq3Ql2o1n3m4p5q6r7", "2026-11-01 10:05:00")],
        ("user_login", 1), ("user_pass", 2)),
    "C:\\wacdata\\wac-outside.db": (
        "wac-outside.db",
        "CREATE TABLE AspNetUsers(Id TEXT PRIMARY KEY, UserName TEXT, PasswordHash TEXT)",
        "INSERT INTO AspNetUsers VALUES(?, ?, ?)",
        [("7f0c5b0e-0000-4000-8000-000000000001", "wacoperator", "AQAAAAIAAYagAAAAEHdhY1dpdG5lc3NIYXNo")],
        ("UserName", 1), ("PasswordHash", 2)),
}


def main():
    folder, reference = sys.argv[1], sys.argv[2]
    with open(reference, "w", encoding="utf-8") as out:
        for path, (name, create, insert, rows, (login, at), (_, hashed_at)) in DATABASES.items():
            connection = sqlite3.connect(os.path.join(folder, name))
            with connection:
                connection.execute(create)
                connection.executemany(insert, rows)
            connection.close()
            for row in rows:
                out.write(f"account={path}|{login}|{row[at]}|{row[hashed_at]}\n")


if __name__ == "__main__":
    main()
