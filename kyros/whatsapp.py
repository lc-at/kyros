import asyncio
import base64
import json

import donna25519
import websockets

from . import constants, utilities


class Whatsapp:
    @classmethod
    async def create(cls):
        whatsapp = cls()
        await whatsapp.connect_ws()
        return whatsapp

    def __init__(self):
        self.client_id = utilities.generate_client_id()
        self.server_id = None

        self.client_token = None
        self.server_token = None

        self.secret = None

        self.private_key = donna25519.PrivateKey()
        self.public_key = self.private_key.get_public()

    async def connect_ws(self):
        self.ws = await websockets.connect(constants.WEBSOCKET_URI,
                                           origin="https://web.whatsapp.com")

    def encode_ws_message(self, obj):
        message_tag = utilities.generate_message_tag()
        message = f"{message_tag},{json.dumps(obj)}"
        return {"tag": message_tag, "data": message}

    def decode_ws_message(self, message):
        tag, json_obj = message.split(",", 1)
        return {"tag": tag, "data": json.loads(json_obj)}

    async def send_init(self):
        await self.ws.send(
            self.encode_ws_message([
                "admin", "init", constants.CLIENT_VERSION,
                [constants.CLIENT_LONG_DESC, constants.CLIENT_SHORT_DESC],
                self.client_id.decode(), True
            ])["data"])
        message = self.decode_ws_message(await self.ws.recv())
        if message["data"]["status"] != 200:
            raise Exception(f"login failed, message: {message}")
        self.server_id = message["data"]["ref"]

    async def qr_login(self):
        await self.send_init()

        async def wait_qr_scan():
            message = self.decode_ws_message(await self.ws.recv())
            self.secret = message["data"][1]['secret']

        qr_fragments = [
            self.server_id,
            base64.b64encode(self.public_key.public).decode(),
            self.client_id.decode()
        ]
        qr = ",".join(qr_fragments)

        return qr, asyncio.wait_for(wait_qr_scan(), 20)
