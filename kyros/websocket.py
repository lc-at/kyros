import asyncio
import json
import logging

import websockets

from . import constants, crypto, exceptions, utilities

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WebsocketMessage:
    """
    `WebsocketMessage` Acts as a container for websockt messages.
    `data` attribute always contains a decoded or decrypted
    data (for binary msg).
    `tag` is also automatically generated if None is given as the tag.
    """
    def __init__(self, tag=None, data=None):
        self.tag = tag
        if not self.tag:
            self.tag = utilities.generate_message_tag()
        self.data = data

        self.is_binary = False

    def encode(self):
        encoded_message = f"{self.tag},{json.dumps(self.data)}"
        return encoded_message

    @classmethod
    def process(cls, message, keys):
        if not isinstance(message, bytes):
            return cls.from_encoded(message)
        return cls.from_encrypted(message, keys)

    @classmethod
    def from_encoded(cls, message):
        tag, encoded_data = message.split(",", 1)
        return cls(tag, json.loads(encoded_data))

    @classmethod
    def from_encrypted(cls, message, keys):
        enc_key, mac_key = keys
        instance = cls()
        instance.is_binary = True

        tag, data = message.split(b",", 1)
        instance.tag = tag

        checksum = data[:32]
        encrypted_data = data[32:]

        if crypto.hmac_sha256(mac_key, encrypted_data) != checksum:
            raise exceptions.HMACValidationError

        instance.data = crypto.aes_decrypt(enc_key, encrypted_data)

        return instance


class WebsocketMessages:
    messages = {}

    def add(self, tag, data):
        self.messages[tag] = data

    def get(self, tag, timeout=10):
        async def get_message():
            while tag not in self.messages:
                await asyncio.sleep(0)
            return self.messages.pop(tag)

        logger.debug("Getting message with tag %s", tag)

        return asyncio.wait_for(get_message(), timeout)


class WebsocketClient:
    websocket = None
    kyros_session = None
    messages = WebsocketMessages()

    def __init__(self, message_handler):
        self.handle_message = message_handler

    async def connect(self):
        logger.debug("Connecting to ws server")
        self.websocket = await websockets.connect(
            constants.WEBSOCKET_URI, origin=constants.WEBSOCKET_ORIGIN)
        logger.debug("Websocket connected")
        self._start_receiver()

    def load_session(self, session):
        self.kyros_session = session

    def _get_keys(self):
        return self.kyros_session.enc_key, self.kyros_session.mac_key

    async def shutdown(self):
        if self.websocket.open:
            logger.debug("Closing websocket server")
            await self.websocket.close()

    def _start_receiver(self):
        async def receiver():
            while True:
                if not self.websocket or not self.websocket.open:
                    logger.debug("receiver returned: no ws/connection closed")
                    return

                if not self.websocket.messages or self.websocket.closed:
                    await asyncio.sleep(0)
                    continue

                raw_message = self.websocket.messages.pop()
                try:
                    message = WebsocketMessage.process(raw_message,
                                                       self._get_keys())
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Ignored error decoding message: %s", exc)
                    await asyncio.sleep(0)
                    continue

                logger.debug("Received WS message with tag %s", message.tag)
                self.messages.add(message.tag, message.data)

        asyncio.ensure_future(receiver())
        logger.debug("Executed receiver coroutine")

    async def send_message(self, message: WebsocketMessage):
        logger.debug("Sending a WS message with tag %s", message.tag)
        await self.websocket.send(message.encode())
