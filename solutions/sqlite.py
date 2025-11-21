import sqlite3
from typing import Optional, Any

def query(query: str) -> Optional[Any]:
    # Path to your database
    db_path = "data/data.db"

    try:
        # Use a context manager so the connection is closed automatically
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute(query)
            result = cur.fetchone()
            return str(result) if result else None
    except Exception:
        # On any error return None
        return None