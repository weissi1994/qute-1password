#!/usr/bin/env python3

import os
import sys
import json
import logging
import argparse
import tempfile
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlsplit

logger = logging.getLogger("qute_1pass")

SESSION_PATH = os.path.join(os.environ["HOME"], ".op", "session")
SESSION_DURATION = timedelta(minutes=120)

LAST_ITEM_PATH = os.path.join(os.environ["HOME"], ".op", "last_items")
LAST_ITEM_DURATION = timedelta(minutes=60)

CMD_ITEM_SELECT = "echo -e '{items}' | wofi -d -p 'Select login'"
CMD_LIST_PROMPT = "echo {items} | wofi -d"

CMD_OP_LOGIN = "pass 1pass | op signin --account ixolit --raw"
CMD_OP_LIST_ITEMS = "op item list --categories Login --session={session_id} --format=json | op item get --session={session_id} - --format json | jq -s 'reduce . as $x ([]; . + $x)'"
CMD_OP_GET_ITEM = "op item get {uuid} --session={session_id} --format json"
CMD_OP_GET_OTP = "ykman oath accounts code \"$(echo -e \"$(ykman oath accounts list)\" | wofi -d -p 'Select OTP')\" | awk '{print $NF}'| sed 's/ *$//g'"

QUTE_FIFO = os.environ["QUTE_FIFO"]

parser = argparse.ArgumentParser()
parser.add_argument(
    "command", help="fill_credentials, fill_totp, fill_username, fill_password"
)
parser.add_argument(
    "--auto-submit", help="Auto submit after filling", action="store_true"
)
parser.add_argument(
    "--cache-session",
    help="Cache 1password session for 30 minutes",
    action="store_true",
)
parser.add_argument(
    "--allow-insecure-sites",
    help="Allow filling credentials on insecure sites",
    action="store_true",
)


class Qute:
    """Logic related to qutebrowser"""

    @classmethod
    def _command(cls, command, *args):
        with open(QUTE_FIFO, "w") as fifo:
            logger.info(f"{command} {' '.join(args)}")
            fifo.write(f"{command} {' '.join(args)}\n")
            fifo.flush()

    @classmethod
    def _message(cls, message, type="error"):
        cls._command(f"message-{type}", f"'qute-1password: {message}'")

    @classmethod
    def message_error(cls, message):
        cls._message(message)

    @classmethod
    def message_warning(cls, message):
        cls._message(message, type="warning")

    @classmethod
    def fake_key(cls, key):
        key = key.replace(" ", "<Space>")
        cls._command("fake-key", key)

    @classmethod
    def fill_credentials_tabmode(cls, username, password, submit=False):
        cls.fake_key(username)
        cls.fake_key("<TAB>")
        cls.fake_key(password)
        if submit:
            cls.fake_key("<Return>")

    @classmethod
    def fill_single_field_tabmode(cls, value, submit=False):
        cls.fake_key(value)
        if submit:
            cls.fake_key("<Return>")

    @classmethod
    def fill_totp(cls, totp, submit=True):
        cls.fake_key(totp)
        if submit:
            cls.fake_key("<Return>")


class ExecuteError(Exception):
    """Used when commands executed return code is not 0"""

    pass


def execute_command(command):
    """Executes a command, mainly used to launch commands for user input and the op cli"""
    result = subprocess.run(command, shell=True, capture_output=True, encoding="utf-8")

    if result.returncode != 0:
        logger.error(result.stderr)
        raise ExecuteError(result.stderr)

    return result.stdout.strip()


def extract_host(url):
    """Extracts the host from a given URL"""
    _, host, *_ = urlsplit(url)
    return host


class OnePass:
    """Logic related to the op command and parsing results"""

    @classmethod
    def login(cls):
        try:
            session_id = execute_command(CMD_OP_LOGIN)
        except ExecuteError:
            Qute.message_error("Login error")
            sys.exit(0)

        if arguments.cache_session:
            with open(SESSION_PATH, "w") as handler:
                handler.write(session_id)

        return session_id

    @classmethod
    def get_session(cls, use_cache=True):
        """
        Returns a session for the op command to make calls with.
        If a session is cached, we check if it's expired first to avoid any errors.
        """
        if arguments.cache_session and os.path.isfile(SESSION_PATH) and use_cache:
            # op sessions last 30 minutes, check if still valid
            creation_time = datetime.fromtimestamp(os.stat(SESSION_PATH).st_ctime)
            if (datetime.now() - creation_time) < SESSION_DURATION:
                return open(SESSION_PATH, "r").read()
            else:
                # Session expired
                os.unlink(SESSION_PATH)

        return cls.login()

    @classmethod
    def list_items(cls):
        session_id = cls.get_session()

        if arguments.cache_session and os.path.isfile(LAST_ITEM_PATH):
            # op sessions last 30 minutes, check if still valid
            creation_time = datetime.fromtimestamp(os.stat(LAST_ITEM_PATH).st_ctime)
            file_size = os.stat(LAST_ITEM_PATH).st_size
            if (datetime.now() - creation_time) < LAST_ITEM_DURATION and file_size > 2:
                return json.loads(open(LAST_ITEM_PATH, "r").read())
            else:
                # Session expired
                os.unlink(LAST_ITEM_PATH)

        print(CMD_OP_LIST_ITEMS.format(session_id=session_id))
        result = execute_command(CMD_OP_LIST_ITEMS.format(session_id=session_id))
        print(result)
        parsed = json.loads(result)
        with open(LAST_ITEM_PATH, "w") as handler:
            handler.write(json.dumps(parsed))
        return parsed

    @classmethod
    def get_item(cls, uuid):
        session_id = cls.get_session()
        try:
            result = execute_command(
                CMD_OP_GET_ITEM.format(uuid=uuid, session_id=session_id)
            )
        except ExecuteError:
            logger.error("Error retrieving credential", exc_info=True)
        parsed = json.loads(result)

        return parsed

    @classmethod
    def get_item_for_url(cls, url):
        host = extract_host(url)

        def filter_host(item):
            """Exclude items that does not match host on any configured URL"""
            if "urls" in item:
                return any(filter(lambda x: host in x["href"], item["urls"]))
            return False

        items = cls.list_items()
        print(items)
        filtered = list(filter(filter_host, items))
        print(filtered)

        if not filtered:
            raise cls.NoItemsFoundError(f"No items found for host {host}")

        mapping = {
            f"{host}: {item['title']} ({item['fields'][0]['value']})": item
            for item in filtered
        }

        credential = None
        try:
            credential = execute_command(
                CMD_ITEM_SELECT.format(items="\n".join(mapping.keys()))
            )
        except ExecuteError:
            pass

        if not credential:
            # Cancelled
            return

        return mapping[credential]

    @classmethod
    def get_credentials(cls, item):
        username = password = None
        print(item)
        for field in item["fields"]:
            if field.get("id") == "username":
                username = field["value"]
            if field.get("id") == "password":
                password = field["value"]

        if username is None or password is None:
            logger.warning(
                "Present: username={username} password={password}".format(
                    username=username is not None, password=password is not None
                )
            )
            Qute.message_warning("Filled incomplete credentials")

        return {"username": username, "password": password}

    @classmethod
    def get_totp(cls):
        try:
            return execute_command(CMD_OP_GET_OTP)
        except ExecuteError:
            logger.error("Error retrieving TOTP", exc_info=True)

    class NoItemsFoundError(Exception):
        pass


class CLI:
    def __init__(self, arguments):
        self.arguments = arguments

    def run(self):
        command = self.arguments.command
        if command != "run" and not command.startswith("_") and hasattr(self, command):
            return getattr(self, command)()

    def _get_item(self):
        try:
            item = OnePass.get_item_for_url(os.environ["QUTE_URL"])
        except OnePass.NoItemsFoundError as error:
            Qute.message_warning("No item found for this site")
            logger.error(f"No item found for site: {os.environ['QUTE_URL']}")
            logger.error(error)
            sys.exit(0)
        return item

    def _fill_single_field(self, field):
        item = self._get_item()
        credentials = OnePass.get_credentials(item)
        Qute.fill_single_field_tabmode(
            credentials[field], submit=self.arguments.auto_submit
        )
        return item

    def fill_username(self):
        item = self._fill_single_field("username")

    def fill_password(self):
        item = self._fill_single_field("password")

    def fill_credentials(self):
        item = self._get_item()
        credentials = OnePass.get_credentials(item)
        Qute.fill_credentials_tabmode(
            *credentials.values(), submit=self.arguments.auto_submit
        )

    def fill_totp(self):
        # Check last item first
        # If theres a last_item file created in the last LAST_ITEM_DURATION seconds
        # and the host matches the one the user is visiting, use that UUID to retrieve
        # the totp
        # item = None

        # if os.path.isfile(LAST_ITEM_PATH):
        #    creation_time = datetime.fromtimestamp(os.stat(LAST_ITEM_PATH).st_ctime)
        #    if (datetime.now() - creation_time) < LAST_ITEM_DURATION:
        #        last_item = json.loads(open(LAST_ITEM_PATH, "r").read())
        #        if last_item["host"] == extract_host(os.environ["QUTE_URL"]):
        #            item = last_item

        # if not item:
        #    item = self._get_item()

        totp = OnePass.get_totp()
        logger.error(totp)
        Qute.fill_totp(totp)

        if os.path.isfile(LAST_ITEM_PATH):
            os.unlink(LAST_ITEM_PATH)


if __name__ == "__main__":
    arguments = parser.parse_args()

    # Prevent filling credentials in non-secure sites if not explicitly allwoed
    if not arguments.allow_insecure_sites:
        if urlsplit(os.environ["QUTE_URL"])[0] != "https":
            Qute.message_error(
                "Trying to fill a non-secure site. If you want to allow it add the --allow-insecure-sites flag."
            )
            logger.error("Refusing to fill credentials on non-secure sites")
            sys.exit(0)

    cli = CLI(arguments)
    sys.exit(cli.run())
