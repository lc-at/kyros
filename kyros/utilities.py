import base64
import os
import time


def generate_message_tag() -> str:
    """Generate a message tag. Spawns a string of
    current timestamp."""
    return str(time.time())


def generate_client_id() -> str:
    """Generates client id, base64 encoded random 16 bytes
    long string."""
    return base64.b64encode(os.urandom(16)).decode()
