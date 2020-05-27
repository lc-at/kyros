import asyncio
import base64
import logging

import donna25519

from . import (constants, crypto, exceptions, message, session, utilities,
               websocket)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Client:
    @classmethod
    async def create(cls):
        instance = cls()
        await instance.setup_ws()
        instance.load_profile(constants.CLIENT_VERSION,
                              constants.CLIENT_LONG_DESC,
                              constants.CLIENT_SHORT_DESC)
        logger.info("Kyros instance created")
        return instance

    def __init__(self):
        self.profile = None
        self.message_handler = message.MessageHandler()
        self.session = session.Session()
        self.session.client_id = utilities.generate_client_id()
        self.session.private_key = donna25519.PrivateKey()
        self.session.public_key = self.session.private_key.get_public()
        self.phone_info = {}
        self.websocket = None

    async def setup_ws(self):
        self.websocket = websocket.WebsocketClient(self.message_handler)
        await self.websocket.connect()

    def load_profile(self, ver, long_desc, short_desc):
        logger.debug("Loaded new profile")
        self.profile = {
            "version": ver,
            "long_description": long_desc,
            "short_description": short_desc,
        }

    async def send_init(self):
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

    async def qr_login(self):
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

    async def restore_session(self, new_session=None):  # noqa: mc0001
        old_session = self.session
        if new_session:
            self.session = new_session

        try:
            await self.send_init()
        except exceptions.StatusCodeError as exc:
            logger.error("Restore session init responded with %d", exc.code)
            return False
        except asyncio.TimeoutError:
            logger.error("Restore session init timed out")
            return False

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
            try:
                login_resp = await self.websocket.messages.get(
                    login_message.tag)
            except asyncio.TimeoutError:
                logger.error("login message timeout")
                return False
            if login_resp["status"] != 200:
                logger.error("login message responded %d",
                             login_resp["status"])
                return False

        if len(s1_message) == 2 and s1_message[0] == "Cmd" \
                and s1_message[1]["type"] == "challenge":
            if not self.resolve_challenge(s1_message["challenge"]):
                logger.error("failed to solve challenge")
                return False

        # THIS IS MY LAST WORKING POINT, STILL INCOMPLETE

        try:
            login_resp = await self.websocket.messages.get(login_message.tag)
        except asyncio.TimeoutError:
            logger.error("timeout w")

        self.session = old_session
        return True

    async def resolve_challenge(self, challenge):
        challenge = base64.b64decode(challenge.encode()).decode()
        signed = crypto.sign_with_mac(challenge, self.session.mac_key)
        chall_reply_message = websocket.WebsocketMessage(
            None, [
                "admin", "challenge",
                base64.b64encode(signed).decode(), self.session.server_token,
                self.session.client_id
            ])
        await self.websocket.send_message(chall_reply_message)

        try:
            status = self.websocket.messages.get(chall_reply_message)["status"]
        except asyncio.TimeoutError:
            logger.error("timeout waiting for chall resolve")
            return False

        if status != 200:
            logger.error("chall resolve responded with %d", status)
            return False

        return True

    async def safe_run(self, func, *args, **kwargs):
        try:
            return None, func(*args, **kwargs)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Exception %s raised at %s", exc, func.__name__)
            return exc, None

    async def logout(self):
        self.websocket.send_message(
            websocket.WebsocketMessage(None, ["admin", "Conn", "disconnect"]))

    async def shutdown(self):
        logger.info("Shutting down")
        await self.websocket.shutdown()
