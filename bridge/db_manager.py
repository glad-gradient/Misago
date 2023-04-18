from datetime import datetime

import psycopg2
from psycopg2 import sql


class AkismetDbManager:
    def __init__(self, table: str):
        self.table = table

    def save(self, data: dict, analyzed_at: datetime, post_id: int, db_creds: dict):
        # https://stackoverflow.com/questions/13793399/passing-table-name-as-a-parameter-in-psycopg2
        print("Akismet Table: ", self.table)
        query = sql.SQL('INSERT INTO {table} (classification, analyzed_at, post_id) VALUES (%s, %s, %s) RETURNING id;').format(table=sql.Identifier(self.table))
        # query = sql.SQL("""
        #     INSERT INTO {table} (
        #         classification,
        #         analyzed_at,
        #         post_id
        #         ) VALUES (%s, %s, %s) RETURNING id;
        #     """).format(table=sql.Identifier(self.table))
        args = (
            data['classification'], analyzed_at,
            post_id
        )
        try:
            with psycopg2.connect(**db_creds) as conn:
                cursor = conn.cursor()
                cursor.execute(query, args)
                return cursor.fetchone()
        except (Exception, psycopg2.Error) as error:
            print("Error while connecting to PostgreSQL: ", error)

    # def save(self, data: dict, analyzed_at: datetime, post_id: int, db_creds: dict):
    #     query = """
    #         INSERT INTO result_akismet (
    #             classification,
    #             analyzed_at,
    #             post_id
    #             ) VALUES (%s, %s, %s) RETURNING id;
    #         """
    #     args = (
    #         data['classification'], analyzed_at,
    #         post_id
    #     )
    #     try:
    #         with psycopg2.connect(**db_creds) as conn:
    #             cursor = conn.cursor()
    #             cursor.execute(query, args)
    #             return cursor.fetchone()
    #     except (Exception, psycopg2.Error) as error:
    #         print("Error while connecting to PostgreSQL: ", error)


class BodyguardDbManager:
    def __init__(self, table: str):
        self.table = table

    def save(self, data: dict, analyzed_at: datetime, post_id: int, db_creds: dict):
        print("Bodyguard Table: ", self.table)

        query = sql.SQL('INSERT INTO {table} (content_type, severity, classifications, directed_at, recommended_action, analyzed_at, post_id) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;').format(table=sql.Identifier(self.table))

        # query = sql.SQL(
        #     """
        #     INSERT INTO {table} (
        #                 content_type,
        #                 severity,
        #                 classifications,
        #                 directed_at,
        #                 recommended_action,
        #                 analyzed_at,
        #                 post_id
        #         ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
        #     """
        # ).format(table=sql.Identifier(self.table))

        args = (
            data['type'],
            data['severity'],
            data['classifications'],
            data['directed_at'],
            data['recommended_action'],
            analyzed_at,
            post_id
        )
        try:
            with psycopg2.connect(**db_creds) as conn:
                cursor = conn.cursor()
                cursor.execute(query, args)
                return cursor.fetchone()
        except (Exception, psycopg2.Error) as error:
            print("Error while connecting to PostgreSQL: ", error)

    # def save(self, data: dict, analyzed_at: datetime, post_id: int, db_creds: dict):
    #     query = """
    #         INSERT INTO result_bodyguard (
    #             content_type,
    #             severity,
    #             classifications,
    #             directed_at,
    #             recommended_action,
    #             analyzed_at,
    #             post_id
    #             ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
    #             """
    #     args = (
    #         data['type'],
    #         data['severity'],
    #         data['classifications'],
    #         data['directed_at'],
    #         data['recommended_action'],
    #         analyzed_at,
    #         post_id
    #     )
    #     try:
    #         with psycopg2.connect(**db_creds) as conn:
    #             cursor = conn.cursor()
    #             cursor.execute(query, args)
    #             return cursor.fetchone()
    #     except (Exception, psycopg2.Error) as error:
    #         print("Error while connecting to PostgreSQL: ", error)