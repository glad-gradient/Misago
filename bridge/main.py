from datetime import datetime, timezone
import logging

import psycopg2
import psycopg2.extensions

from detector import AkismetDetector, BodyguardDetector
from db_manager import AkismetDbManager, BodyguardDbManager
from utils import environment_variables


def main():
    logging.info("Listening 'message_events' channel")

    # DB_ENV_VARS = environment_variables('/home/gradient/projects/nestlogic/spam_detector_eval/simulation/forum/Misago/postgredb.env')
    DB_ENV_VARS = environment_variables('postgredb.env')

    db_name = DB_ENV_VARS['POSTGRES_DB']
    user = DB_ENV_VARS['POSTGRES_USER']
    password = DB_ENV_VARS['POSTGRES_PASSWORD']
    host = DB_ENV_VARS['POSTGRES_HOST']

    db_creds = dict(database=db_name, user=user, password=password, host=host)

    # Connect to the database
    conn = psycopg2.connect(**db_creds)

    # Set the connection to asynchronous mode
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    # Create a new database cursor
    cur = conn.cursor()

    # Listen for notifications on the "message_events" channel
    cur.execute("LISTEN message_events;")

    akis_det = AkismetDetector()
    body_det = BodyguardDetector()

    while True:
        # Wait for a notification
        conn.poll()  # This method blocks until a notification is received, so we can use it to wait for new notifications without wasting CPU cycles.

        # Get all notifications
        while conn.notifies:
            # Process each notification
            notify = conn.notifies.pop(0)
            print("Received notification on channel", notify.channel, "with payload", notify.payload, "payload type ", type(notify.payload))

            post_id = int(notify.payload)
            # Akismet
            result = akis_det.pipeline(str(post_id), db_creds)
            analyzed_at = datetime.now().replace(tzinfo=timezone.utc)
            AkismetDbManager().save(
                {'classification': result},
                analyzed_at,
                post_id,
                db_creds
            )

            # Bodyguard
            result = body_det.pipeline(str(post_id), db_creds)
            if isinstance(result, list):
                result = result[0]
            analyzed_at = result.pop('analyzed_at', None)
            if analyzed_at:
                analyzed_at = datetime.fromisoformat(analyzed_at[:-1])
            else:
                analyzed_at = datetime.now().replace(tzinfo=timezone.utc)
            BodyguardDbManager().save(
                result,
                analyzed_at,
                post_id,
                db_creds
            )


if __name__ == "__main__":
    main()
