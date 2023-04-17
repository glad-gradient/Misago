from abc import ABC
import json
import logging

import requests
import psycopg2
import psycopg2.extensions

from akismet import Akismet


def dictfetchall(cursor):
    """
    Return all rows from a cursor as a dict
    :param cursor:
    :return:
    """
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]


class SpamDetector(ABC):
    def get_data(self, record_id: str, db_creds: dict):
        """

        :param record_id: db record id expected
        :return:
        """

        record_id = int(record_id)

        query = """
            SELECT p.id AS comment_id, p.original AS message, p.posted_on AS comment_time,
                u.id AS user_id, u.username, u.slug AS user_slug, u.email, u.joined_from_ip AS user_ip,
                t.id AS thread_id,
                t.title AS original_title,
                t.slug AS title,
                t.started_on AS thread_time
                FROM public.misago_threads_post AS p, public.misago_users_user AS u, public.misago_threads_thread AS t
            WHERE p.id = %s 
                AND p.thread_id = t.id AND p.poster_id = u.id
        """

        args = (record_id,)
        try:
            with psycopg2.connect(**db_creds) as conn:
                cursor = conn.cursor()
                cursor.execute(query, args)
                return dictfetchall(cursor)
        except (Exception, psycopg2.Error) as error:
            print("Error while connecting to PostgreSQL: ", error)

    def prepare_data_for_API_detector(self, data):
        raise NotImplementedError

    def evaluate(self, **kwargs):
        raise NotImplementedError

    def pipeline(self, record_id: str, db_creds: dict):
        data = self.get_data(record_id, db_creds)
        data_prepared = self.prepare_data_for_API_detector(data[0])
        return self.evaluate(**data_prepared)


class AkismetDetector(SpamDetector):
    def __init__(self, use_single_proxy=True, use_single_user_agent=True):
        self.use_single_proxy = use_single_proxy
        self.proxies = self._get_proxies()
        self.use_single_user_agent = use_single_user_agent
        self.user_agents = self._user_agents()

    def _get_proxies(self):
        with open('ip_addresses.json') as f:
            return json.load(f)

    def _user_agents(self):
        with open('user_agents.json') as f:
            return json.load(f)

    def prepare_data_for_API_detector(self, data):
        with open('configs.json') as f:
            configs = json.load(f)

        protocol = configs["PROTOCOL"]
        APP_IP = configs["HOST"]
        APP_PORT = configs["PORT"]
        blog_url = "{protocol}://{app_ip}:{app_port}".format(protocol=protocol, app_ip=APP_IP, app_port=APP_PORT)

        kwargs = dict()

        kwargs["user_ip"] = data["user_ip"] if "user_ip" in data else "127.0.0.1"
        if self.use_single_proxy and "username" in data and data["username"] in self.proxies:
            print('Proxy. I am here!')
            kwargs["user_ip"] = self.proxies[data["username"]]

        kwargs["user_agent"] = data["user_agent"] if "user_agent" in data else "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
        if self.use_single_user_agent and "username" in data and data["username"] in self.user_agents:
            kwargs["user_agent"] = self.user_agents[data["username"]]

        if "username" in data:
            kwargs["comment_author"] = data["username"]

        if "email" in data:
            kwargs["comment_author_email"] = data["email"]

        if "message" in data:
            kwargs["comment_content"] = data["message"]

        # permalink - The full permanent URL of the entry the comment was submitted to.
        if "title" in data and "thread_id" in data:
            kwargs["permalink"] = "{url}/t/{title}/{thread_id}/".format(
                url=blog_url,
                title=data["title"], thread_id=data["thread_id"]
            )

        # comment_type
        kwargs["comment_type"] = "reply"

        if "comment_time" in data:
            kwargs["comment_date"] = data["comment_time"] # .isoformat()

        # if "thread_time" in data:
        #     kwargs["comment_post_modified_gmt"] = data["thread_time"].isoformat()

        return kwargs

    def evaluate(self, **kwargs):
        with open('configs.json') as f:
            configs = json.load(f)

        protocol = configs["PROTOCOL"]
        APP_IP = configs["HOST"]
        APP_PORT = configs["PORT"]
        blog_url = "{protocol}://{app_ip}:{app_port}".format(protocol=protocol, app_ip=APP_IP, app_port=APP_PORT)

        akismet_cfgs = configs["DETECTORS"]["Akismet"]
        API_KEY = akismet_cfgs["API_KEY"]
        akismet_user_agent = None

        akismet = Akismet(
            api_key=API_KEY,
            blog=blog_url,
            application_user_agent=akismet_user_agent,
            is_test=True
        )

        user_ip = kwargs.pop('user_ip', "127.0.0.1")
        user_agent = kwargs.pop('user_agent', "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0")

        label = akismet.check(user_ip=user_ip, user_agent=user_agent, **kwargs)

        if label in [0, 1]:
            return 'Ham'
        elif label in [2, 3]:
            return 'Spam'
        else:
            return label


class BodyguardDetector(SpamDetector):
    """
        {
        "channelId": "$YOUR_CHANNEL_ID",
        "contents": [
            {
                "text": "New video available !",
                "reference": "78568088",
                "publishedAt": "2022-10-03T03:42:00.420Z",
                "context": {
                    "topLevelReference": "78568088",  # Allows you to link this message to the top level message. Example: e.g first/original post.
                    # parentReference: Allows you to link this message to a parent message.
                    "permalink": # Allows you to link the analyzed message to the original message on the platform.
                    "from": {
                        "type": "AUTHOR",
                        "data": {
                            "identifier": "9131", +
                            "profilePictureURL": ,
                            "username": "Charles", +
                            "permalink":  "http://127.0.0.1:8000/u/user5/4/posts/",  # A permalink to the user associated with this author on your platform.
    #                         "birthdate": "1996-10-19",
    #                         "gender": "MALE"
                        }
                    },
                    "post": {
                        "type": "TEXT",
                        "data": {
                            "identifier": "5468b255562e",
                            "title": "Nice content",
                            "publishedAt":,
                            "permalink": # A permalink to the post on your platform.
                        }
                    }
                }
            }
        ]
    }
    """
    def prepare_data_for_API_detector(self, data):
        with open('configs.json') as f:
            configs = json.load(f)

        protocol = configs["PROTOCOL"]
        APP_IP = configs["HOST"]
        APP_PORT = configs["PORT"]
        blog_url = "{protocol}://{app_ip}:{app_port}".format(protocol=protocol, app_ip=APP_IP, app_port=APP_PORT)

        kwargs = dict()

        if "message" in data:
            kwargs["text"] = data["message"]

        # reference  http://127.0.0.1:8000/t/learn-python/1/post/7/
        if "title" in data and "thread_id" in data and "comment_id" in data:
            kwargs["reference"] = "{title}/{thread_id}/post/{comment_id}/".format(
                title=data["title"],
                thread_id=data["thread_id"],
                comment_id=data["comment_id"]
            )

        if "comment_time" in data:
            kwargs["publishedAt"] = str(data["comment_time"].isoformat())

        # *************************** Context *****************************
        context = {}
        # topLevelReference: Allows you to link this message to the top level message. Example: e.g first/original post.
        if "title" in data and "thread_id" in data:
            context["topLevelReference"] = "{title}/{thread_id}".format(title=data["title"], thread_id=data["thread_id"])

        # "parentReference": "", # Allows you to link this message to a parent message.
        # permalink: Allows you to link the analyzed message to the original message on the platform.
        if "title" in data and "thread_id" in data and "comment_id" in data:
            context["permalink"] = "{url}/t/{title}/{thread_id}/post/{comment_id}/".format(
                url=blog_url,
                title=data["title"], thread_id=data["thread_id"], comment_id=data["comment_id"]
            )

        # ******************** Sender **********************
        sender = {
            "type": "AUTHOR",
            "data": {}
        }
        sender_data = sender["data"]
        if "user_id" in data:
            sender_data["identifier"] = str(data["user_id"])
        else:
            raise Exception("User identifier is required")

        # profilePictureURL

        # username
        if "username" in data:
            sender_data["username"] = data["username"]

        # user permalink.
        # A permalink to the user associated with this author on your platform. http://127.0.0.1:8000/u/user5/4/posts/
        if "user_slug" in data and "user_id" in data:
            sender_data["permalink"] = "{url}/u/{user_slug}/{user_id}/posts/".format(
                url=blog_url,
                user_slug=data["user_slug"], user_id=data["user_id"]
            )

        context["from"] = sender

        # ********************** Post ************************
        post = {
            "type": "TEXT",
            "data": {}
        }
        post_data = post["data"]

        if "thread_id" in data:
            post_data["identifier"] = str(data["thread_id"])
        else:
            raise Exception("Post identifier is required")

        if "original_title" in data:
            post_data["title"] = data["original_title"]
        if "thread_time" in data:
            post_data["publishedAt"] = str(data["thread_time"].isoformat())

        # A permalink to the post on your platform.
        if "title" in data and "thread_id" in data:
            post_data["permalink"] = "{url}/t/{title}/{thread_id}/".format(
                url=blog_url,
                title=data["title"], thread_id=data["thread_id"]
            )
        context["post"] = post

        kwargs["context"] = context

        return kwargs

    def evaluate(self, **kwargs):
        with open('configs.json') as f:
            configs = json.load(f)

        bodyguard_cfgs = configs["DETECTORS"]["Bodyguard"]
        API_KEY = bodyguard_cfgs["API_KEY"]
        channel_id = bodyguard_cfgs["CHANNEL_ID"]

        headers = {
            'X-Api-Key': API_KEY,
            'Content-Type': 'application/json'
        }
        url = 'https://bamboo.bodyguard.ai/api/analyze'

        # date = str(datetime.utcnow().isoformat()[: -3] + 'Z')
        # date = str(datetime.utcnow().isoformat() + 'Z')

        contents = [kwargs]
        # contents = [{"text": text, "publishedAt": date}]

        payload = {"channelId": channel_id, "contents": contents}
        payload = json.dumps(payload)

        resp = requests.post(url, data=payload, headers=headers)

        resp_data = resp.json()

        result = list()
        if "data" in resp_data:
            for item in resp_data["data"]:
                temp = dict()
                temp["type"] = item["type"]  # "NEUTRAL"
                temp["severity"] = item["severity"]  # "NONE"
                temp["classifications"] = ",".join(item["meta"]["classifications"])
                temp["directed_at"] = item["meta"]["directedAt"]  # None
                temp["analyzed_at"] = item["analyzedAt"]
                temp["recommended_action"] = item["recommendedAction"]
                result.append(temp)
        elif "errors" in resp_data:
            for item in resp_data["errors"]:
                logging.error(item)
        else:
            logging.warning("Bodyguard. Unknown response")

        return result






