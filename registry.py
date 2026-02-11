import aiosqlite
import logging

class Registry:
    def __init__(self, db_path):
        self.db_path = db_path

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            # Check if the new schema already exists
            tbl_info = await db.execute_fetchall("PRAGMA table_info(registrations);")
            existing_cols = {row[1] for row in tbl_info}

            expected_cols = {
                "msisdn",
                "ip_addr",
                "visited_network",
                "access_network_info",
                "charging_vector",
                "expiry",
            }

            if existing_cols and expected_cols.issubset(existing_cols):
                # Up-to-date
                await db.commit()
                return

            logger = logging.getLogger("registry")
            if existing_cols:
                logger.warning("Registry schema outdated – recreating table (data will be lost in dev mode)")
                await db.execute("DROP TABLE IF EXISTS registrations;")

            await db.execute('''
                CREATE TABLE registrations (
                    msisdn TEXT PRIMARY KEY,
                    ip_addr TEXT,
                    visited_network TEXT,
                    access_network_info TEXT,
                    charging_vector TEXT,
                    expiry INTEGER
                );
            ''')
            await db.commit()

    async def add_or_update(self, msisdn, ip_addr, visited_network, access_network_info, charging_vector, expiry):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                INSERT OR REPLACE INTO registrations (msisdn, ip_addr, visited_network, access_network_info, charging_vector, expiry)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (msisdn, ip_addr, visited_network, access_network_info, charging_vector, expiry))
            await db.commit()

    async def get(self, msisdn):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute('SELECT * FROM registrations WHERE msisdn = ?', (msisdn,)) as cursor:
                return await cursor.fetchone() 