import psycopg2


class RequestRepository:
    def __init__(self):
        self.db = psycopg2.connect("dbname=proxy_db user=postgres password=postgres")

    def insert_request(self, req: str, host: str, tls: int):
        cur = self.db.cursor()
        cur.execute("INSERT INTO requests(host, request, tls) VALUES(%s, %s, %s)", (host, req, tls))
        self.db.commit()
        cur.close()

    def select_requests(self):
        cur = self.db.cursor()
        cur.execute("SELECT id, host, request, tls FROM requests")
        result = cur.fetchall()
        return result

    def select_request_by_id(self, id: int):
        cur = self.db.cursor()
        cur.execute("SELECT id, host, request, tls FROM requests WHERE id=%s", (id,))
        result = cur.fetchone()
        return result
