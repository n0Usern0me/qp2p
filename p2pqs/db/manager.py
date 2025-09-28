


import os

import sqlite3

import threading

from typing import List, Optional, Dict, Any

from datetime import datetime



MAX_ENTRIES = 100000



class DatabaseManager:

    """Single database manager for all data"""

    

    def __init__(self, db_path: str = "p2p_data.db"):

        self.db_path = db_path

        self.lock = threading.RLock()

        self._initialize_database()



    def _initialize_database(self):

        """Initialize database with single unified table"""

        with self.lock:

            connection = sqlite3.connect(self.db_path, timeout=10.0)

            connection.execute("PRAGMA journal_mode=WAL")

            connection.execute("PRAGMA busy_timeout=10000")

            

            cursor = connection.cursor()

            

            cursor.execute('''

                CREATE TABLE IF NOT EXISTS unified_data (

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    type TEXT NOT NULL,

                    name TEXT NOT NULL,

                    data_json TEXT NOT NULL,

                    encrypted_content BLOB,

                    signature TEXT,

                    owner_id TEXT,

                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

                );

            ''')

            

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON unified_data(type)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_name ON unified_data(name)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_owner ON unified_data(owner_id)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_created ON unified_data(created_at)')

            

            connection.commit()

            connection.close()



    def _get_connection(self):

        """Get database connection"""

        connection = sqlite3.connect(self.db_path, timeout=10.0)

        connection.execute("PRAGMA journal_mode=WAL")

        connection.execute("PRAGMA busy_timeout=10000")

        return connection



    def _cleanup_old_entries(self, entry_type: str):

        """Remove old entries if exceeding limit"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                cursor.execute("SELECT COUNT(*) FROM unified_data WHERE type = ?", (entry_type,))

                count = cursor.fetchone()[0]

                

                if count >= MAX_ENTRIES:

                    delete_count = count - MAX_ENTRIES + 1000

                    cursor.execute('''

                        DELETE FROM unified_data 

                        WHERE type = ? AND id IN (

                            SELECT id FROM unified_data 

                            WHERE type = ? 

                            ORDER BY created_at ASC 

                            LIMIT ?

                        )

                    ''', (entry_type, entry_type, delete_count))

                    connection.commit()

                

                connection.close()

        except Exception as e:

            print(f"[Database] Cleanup error: {e}")



    def store_site(self, site_name: str, owner_id: str, keys_data: Dict[str, str]) -> bool:

        """Store site registration data"""

        try:

            self._cleanup_old_entries("site")

            

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                import json

                data_json = json.dumps({

                    "falcon_private": keys_data.get("falcon_private"),

                    "falcon_public": keys_data.get("falcon_public"),

                    "dilithium_private": keys_data.get("dilithium_private"),

                    "dilithium_public": keys_data.get("dilithium_public"),

                    "created_date": datetime.now().strftime('%Y-%m-%d') 

                })

                

                cursor.execute('''

                    INSERT OR REPLACE INTO unified_data 

                    (type, name, data_json, owner_id) 

                    VALUES (?, ?, ?, ?)

                ''', ("site", site_name, data_json, owner_id))

                

                connection.commit()

                connection.close()

                return True

                

        except Exception as e:

            print(f"[Database] Store site error: {e}")

            return False



    def get_sites(self, limit: int = 100) -> List[Dict[str, Any]]:

        """Get all sites with simplified format"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                cursor.execute('''

                    SELECT name, data_json, owner_id, created_at 

                    FROM unified_data 

                    WHERE type = 'site' 

                    ORDER BY created_at DESC 

                    LIMIT ?

                ''', (limit,))

                

                rows = cursor.fetchall()

                connection.close()

                

                import json

                sites = []

                for row in rows:

                    try:

                        data = json.loads(row[1])

                  

                        created_date = datetime.fromisoformat(row[3].replace('Z', '+00:00')).strftime('%Y-%m-%d')

                        

                        sites.append({

                            "site_name": row[0],

                            "created_date": data.get("created_date", created_date),

                            "falcon_public": data.get("falcon_public"),

                            "dilithium_public": data.get("dilithium_public")

                        })

                    except Exception:

                        continue

                

                return sites

                

        except Exception as e:

            print(f"[Database] Get sites error: {e}")

            return []



    def get_site_keys(self, site_name: str) -> Optional[Dict[str, str]]:

        """Get private keys for a site"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                cursor.execute('''

                    SELECT data_json 

                    FROM unified_data 

                    WHERE type = 'site' AND name = ?

                ''', (site_name,))

                

                row = cursor.fetchone()

                connection.close()

                

                if row:

                    import json

                    return json.loads(row[0])

                return None

                

        except Exception as e:

            print(f"[Database] Get site keys error: {e}")

            return None



    def store_site_public_keys(self, site_name: str, keys_data: Dict[str, str]) -> bool:

        """Store public keys for external sites"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                import json

                data_json = json.dumps({

                    "falcon_public": keys_data.get("falcon_public"),

                    "dilithium_public": keys_data.get("dilithium_public"),

                    "is_external": True,

                    "created_date": datetime.now().strftime('%Y-%m-%d')

                })

                

                cursor.execute('''

                    INSERT OR IGNORE INTO unified_data 

                    (type, name, data_json, owner_id) 

                    VALUES (?, ?, ?, ?)

                ''', ("site", site_name, data_json, "external"))

                

                connection.commit()

                connection.close()

                return True

                

        except Exception as e:

            print(f"[Database] Store public keys error: {e}")

            return False



    def store_content(self, site_name: str, content: str, author_id: str, 

                     encrypted_data: bytes = None, signature: str = None) -> bool:

        """Store content data with simplified format"""

        try:

            self._cleanup_old_entries("content")

            

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                import json

             

                data_json = json.dumps({

                    "site_name": site_name,

                    "content": content,

                    "date": datetime.now().strftime('%Y-%m-%d')  

                })

                

                cursor.execute('''

                    INSERT INTO unified_data 

                    (type, name, data_json, encrypted_content, signature, owner_id) 

                    VALUES (?, ?, ?, ?, ?, ?)

                ''', ("content", f"content_{datetime.now().timestamp()}", 

                     data_json, encrypted_data, signature, author_id))

                

                connection.commit()

                connection.close()

                return True

                

        except Exception as e:

            print(f"[Database] Store content error: {e}")

            return False



    def get_content(self, site_name: str = None, author_id: str = None, 

                   limit: int = 50) -> List[Dict[str, Any]]:

        """Get content data with cleaned up format"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                query = "SELECT data_json, encrypted_content, signature, owner_id, created_at FROM unified_data WHERE type = 'content'"

                params = []

                

                if site_name:

                    query += " AND data_json LIKE ?"

                    params.append(f'%"site_name": "{site_name}"%')

                    

                if author_id:

                    query += " AND owner_id = ?"

                    params.append(author_id)

                

                query += " ORDER BY created_at DESC LIMIT ?"

                params.append(limit)

                

                cursor.execute(query, params)

                rows = cursor.fetchall()

                connection.close()

                

                import json

                contents = []

                for row in rows:

                    try:

                        data = json.loads(row[0])

                        

                        

                        content_entry = {

                            "site_name": data.get("site_name"),

                            "content": data.get("content"),

                            "date": data.get("date"),   

                            "signature": row[2]

                        }

                        

                        

                        if row[1]:

                            content_entry["encrypted_content"] = row[1]

                        

                        contents.append(content_entry)

                    except Exception:

                        continue

                

                return contents

                

        except Exception as e:

            print(f"[Database] Get content error: {e}")

            return []



    def register_node(self, node_id: str, public_keys: Dict[str, str]) -> bool:

        """Register active node"""

        try:

            with self.lock:

                connection = self._get_connection()

                cursor = connection.cursor()

                

                import json

                data_json = json.dumps({

                    "falcon_public": public_keys.get("falcon_public"),

                    "dilithium_public": public_keys.get("dilithium_public"),

                    "last_seen": datetime.now().strftime('%Y-%m-%d')

                })

                

                cursor.execute('''

                    INSERT OR REPLACE INTO unified_data 

                    (type, name, data_json, owner_id) 

                    VALUES (?, ?, ?, ?)

                ''', ("node", node_id, data_json, node_id))

                

                connection.commit()

                connection.close()

                return True

                

        except Exception as e:

            print(f"[Database] Register node error: {e}")

            return False