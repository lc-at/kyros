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
        logger.debug("Kyros instance created")
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
        await self.websocket.start_receiving()

    def load_profile(self, ver, long_desc, short_desc):
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
            raise exceptions.LoginError(f"resp: {resp}")

        self.session.server_id = resp["ref"]

    async def qr_login(self):
        await self.send_init()

        async def wait_qr_scan():
            ws_message = await self.websocket.messages.get("s1")
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

        return qr_data, asyncio.wait_for(wait_qr_scan(), 20)

    async def shutdown(self):
        await self.websocket.stop_receiving()
        await self.websocket.websocket.close()
