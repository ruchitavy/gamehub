import sqlite3

conn = sqlite3.connect("db.sqlite")

conn.execute('''CREATE TABLE IF NOT EXISTS user ( 
                    id integer PRIMARY KEY,
                    name text NOT NULL,
                    email text NOT NULL,
                    password text NOT NULL                
                );''')

conn.commit()
conn.close()
