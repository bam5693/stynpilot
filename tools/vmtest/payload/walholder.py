"""Keeps the pairing database open in WAL mode with committed rows that live ONLY in the -wal file (like a running service)."""
import sqlite3, sys, time
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute("PRAGMA journal_mode=WAL")
db.execute("PRAGMA wal_autocheckpoint=0")
db.execute("CREATE TABLE IF NOT EXISTS wal_marker(v TEXT)")
db.execute("INSERT INTO wal_marker VALUES ('ONLY-IN-THE-WAL')")
print("ready", flush=True)
time.sleep(100000)
