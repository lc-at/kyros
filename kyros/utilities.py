import base64
import os
import time


def generate_message_tag() -> str:
    return str(time.time())


def generate_client_id() -> bytes:
    return base64.b64encode(os.urandom(16))
