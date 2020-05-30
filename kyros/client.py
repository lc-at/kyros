from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any, Awaitable, Callable, Sequence, Union

import donna25519

from . import (constants, crypto, exceptions, message, session, utilities,
               websocket)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Client:
    """This class is the wrapper for WhatsApp Web.
    Errors mainly shown as log messages (using `logging`).
    Some methods might raise an exception that will interrupt the
    whole session. Please make sure to catch any exception thrown.
    You might want to use the `Client.ensure_safe` method.
    Please note that some exceptions should not be ignored as it might
    be important (example: a timeout error when sending a message will
    result in the failing of message delivery). A much better and pythonic
    way to handle and raise exception is still a pending task."""
    @classmethod
    async def create(cls) -> Client:
        """The proper way to instantiate `Client` class. Connects to
        websocket server, also sets up the default client profile.
        Returns a ready to use `Client` instance."""
        instance = cls()
        await instance.setup_ws()
        instance.load_profile(constants.CLIENT_VERSION,
                              constants.CLIENT_LONG_DESC,
                              constants.CLIENT_SHORT_DESC)
        logger.info("Kyros instance created")
        return instance

    def __init__(self) -> None:
        """Initiate class. Do not initiate this way, use `Client.create()`
        instead."""
        self.profile = None
        self.message_handler = message.MessageHandler()
        self.session = session.Session()
        self.session.client_id = utilities.generate_client_id()
        self.session.private_key = donna25519.PrivateKey()
        self.session.public_key = self.session.private_key.get_public()
        self.phone_info = {}
        self.websocket = None

    async def setup_ws(self) -> None:
        """Connect to websocket server."""
        self.websocket = websocket.WebsocketClient(self.message_handler)
        await self.websocket.connect()
        self.websocket.load_session(self.session)

    def load_profile(self, ver: Sequence[Union[float, int]], long_desc: str,
                     short_desc: str) -> None:
        """Loads a new client profile (which will be shown in the WhatsApp
        mobile app). Please note that the client profile is unchangeable after
        logging in (after admin init)."""
        logger.debug("Loaded new profile")
        self.profile = {
            "version": ver,
            "long_description": long_desc,
            "short_description": short_desc,
        }

    async def send_init(self) -> None:
        """Send an admin init message. Usually not used directly. Used whens
        doing QR login or restoring session."""
        init_message = websocket.WebsocketMessage(None, [
            "admin", "init", self.profile["version"],
            [
                self.profile["long_description"],
                self.profile["short_description"]
            ], self.session.client_id, True
        ])
        await self.websocket.send_message(init_message)

        resp = await self.websocket.messages.get(init_message.tag)
        if resp["status"] != 200:
            logger.error("unexpected init stts code, resp:%s", resp)
            raise exceptions.StatusCodeError(resp["status"])

        self.session.server_id = resp["ref"]

    async def qr_login(self) -> (str, Awaitable):
        """Does a QR login. Sends init then return the qr data
        which will be shown using `pyqrcode` or another library and.
        also returns a waitable which will timeout in 20 seconds.
        20 seconds is the maximum amount of time for the QR code to be
        considered valid.
        Raises `asyncio.TimeoutError` if timeout reached.
        Another exception might also possible."""
        await self.send_init()

        async def wait_qr_scan():
            ws_message = await self.websocket.messages.get("s1", 20)
            connection_data = ws_message[1]

            self.phone_info = connection_data["phone"]
            self.session.secret = base64.b64decode(
                connection_data["secret"].encode())
            self.session.server_token = connection_data["serverToken"]
            self.session.client_token = connection_data["clientToken"]
            self.session.browser_token = connection_data["browserToken"]
            self.session.wid = connection_data["wid"]

            self.session.shared_secret = self.session.private_key.do_exchange(
                donna25519.PublicKey(self.session.secret[:32]))
            self.session.shared_secret_expanded = crypto.hkdf_expand(
                self.session.shared_secret, 80)

            if not crypto.validate_secrets(
                    self.session.secret, self.session.shared_secret_expanded):
                raise exceptions.HMACValidationError

            self.session.keys_encrypted = self.session.shared_secret_expanded[
                64:] + self.session.secret[64:]
            self.session.keys_decrypted = crypto.aes_decrypt(
                self.session.shared_secret_expanded[:32],
                self.session.keys_encrypted)

            self.session.enc_key = self.session.keys_decrypted[:32]
            self.session.mac_key = self.session.keys_decrypted[32:64]
            print(self.session.enc_key, self.session.mac_key)

        qr_fragments = [
            self.session.server_id,
            base64.b64encode(self.session.public_key.public).decode(),
            self.session.client_id
        ]
        qr_data = ",".join(qr_fragments)

        return qr_data, wait_qr_scan()

    async def restore_session(  # noqa: mc0001
            self, new_session: session.Session = None) -> session.Session:
        """Restores a session. Returns the new session object.
        If `new_session` argument specified, replace current session with
        the new one.
        Raises asyncio.TimeoutError when a websocket request reaches timeout.
        Old session is restored when it fails restoring the new one."""
        old_session = self.session
        if new_session:
            self.session = new_session

        async def restore():
            await self.send_init()

            login_message = websocket.WebsocketMessage(None, [
                "admin", "login", self.session.client_token,
                self.session.server_token, self.session.client_id, "takeover"
            ])
            await self.websocket.send_message(login_message)

            s1_message = None
            try:
                s1_message = await self.websocket.messages.get("s1")
            except asyncio.TimeoutError:
                logger.error("s1 message timed out")

                login_resp = await self.websocket.messages.get(
                    login_message.tag)
                if login_resp["status"] != 200:
                    raise exceptions.StatusCodeError(login_resp["status"])
                self.websocket.messages.add(login_message.tag, login_resp)

            s2_message = None
            if len(s1_message) == 2 and s1_message[0] == "Cmd" \
                    and s1_message[1]["type"] == "challenge":
                if not self.resolve_challenge(s1_message["challenge"]):
                    logger.error("failed to solve challenge")
                    return False

                s2_message = self.websocket.messages.get("s2")

            login_resp = await self.websocket.messages.get(login_message.tag)
            if login_resp["status"] != 200:
                raise exceptions.StatusCodeError(login_resp["status"])

            conn_resp = s2_message if s2_message else s1_message
            self.phone_info = conn_resp["phone"]
            self.session.wid = conn_resp["wid"]
            self.session.client_token = conn_resp["clientToken"]
            self.session.server_token = conn_resp["serverToken"]

            self.websocket.load_session(self.session)  # reload references

            return self.session

        try:
            return await restore()
        except Exception:  # pylint: disable=broad-except
            if old_session:
                self.session = old_session
            raise

    async def resolve_challenge(self, challenge: str) -> None:
        """Resolve a challenge string. Sings challenge with mac_key and send
        a challenge response ws message. Usually called when restoring session.
        Raises `asyncio.TimeoutError` when timeout reached."""
        challenge = base64.b64decode(challenge.encode()).decode()
        signed = crypto.hmac_sha256(self.session.mac_key, challenge)

        chall_reply_message = websocket.WebsocketMessage(
            None, [
                "admin", "challenge",
                base64.b64encode(signed).decode(), self.session.server_token,
                self.session.client_id
            ])
        await self.websocket.send_message(chall_reply_message)

        status = self.websocket.messages.get(chall_reply_message)["status"]
        if status != 200:
            raise exceptions.StatusCodeError(status)

        return

    async def ensure_safe(self, func: Callable, *args: Any,
                          **kwargs: Any) -> (Union[None, Exception], Any):
        """A function intended to be used to run another function without
        raising any exception. Returns an exception as first element of
        the tuple if available. Also returns the result of the function call
        as the second element of the tuple if no exceptions raised. If `func`
        is a coroutine function, this function returns the awaited result.
        """
        try:
            return_value = func(*args, **kwargs)
            if asyncio.iscoroutine(return_value):
                return None, await return_value
            return None, return_value
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Exception %s raised at %s", exc, func.__name__)
            return exc, None

    async def logout(self) -> None:
        """Sends a logout message to the websocket server. This will
        invalidate the session."""
        await self.websocket.send_message(
            websocket.WebsocketMessage(None, ["admin", "Conn", "disconnect"]))

    async def shutdown(self) -> None:
        """Do a cleanup. Closes websocket connection."""
        logger.info("Shutting down")
        await self.websocket.shutdown()
