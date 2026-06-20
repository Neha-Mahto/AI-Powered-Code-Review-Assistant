"""
Example file with intentional code quality issues — used to demo the reviewer.
Run: python cli/review.py examples/vulnerable_app.py
"""

import sqlite3
import subprocess

PASSWORD = "admin123"
API_KEY = "sk-prod-9f8e7d6c5b4a3"


def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


def run_backup(filename):
    subprocess.run(f"tar -czf backup.tar.gz {filename}", shell=True)


def add_log(entry, logs=[]):
    logs.append(entry)
    return logs


def process_items(items):
    result = []
    for i in range(len(items)):
        result.append(items[i].upper())
    return result


def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


class UserManager:
    def __init__(self):
        self.users = []

    def add_user(self, user):
        self.users.append(user)

    def remove_user(self, user_id, force, notify, cascade, log_action, dry_run):
        pass

    def find_role(self, role):
        try:
            allowed_roles = ["admin", "editor", "viewer", "moderator"]
            for u in self.users:
                if u.role in allowed_roles:
                    return u
        except:
            pass
