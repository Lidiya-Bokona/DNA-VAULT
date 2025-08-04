import sqlite3

DATABASE = 'user_data.db'

def verify_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Query to list all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Tables in the database:", tables)

    # Query to list columns in the `users` table
    cursor.execute("PRAGMA table_info(users);")
    users_columns = cursor.fetchall()
    print("\nColumns in `users` table:")
    for column in users_columns:
        print(column)

    # Query to list columns in the `files` table
    cursor.execute("PRAGMA table_info(files);")
    files_columns = cursor.fetchall()
    print("\nColumns in `files` table:")
    for column in files_columns:
        print(column)

    conn.close()

if __name__ == '__main__':
    verify_db()
