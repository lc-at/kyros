from __future__ import annotations

import asyncio
import json
import logging
from typing import AnyStr, Optional, Sequence, Union

import websockets

from . import constants, crypto, exceptions, utilities
from .message import MessageHandler
from .session import Session

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Timer:
    def __init__(self, timeout, callback):
        self._timeout = timeout
        self._callback = callback
        self._task = asyncio.ensure_future(self._job())

    async def _job(self):
        await asyncio.sleep(self._timeout)
        await self._callback()

    def cancel(self):
        self._task.cancel()


class WebsocketMessage:
    """
    `WebsocketMessage` acts as a container for websocket messages.
    `data` attribute always contains a decoded or decrypted
    data (for binary messages).
    `tag` is also automatically generated if None is given as the tag.
    """

    def __init__(self,
                 tag: Optional[str] = None,
                 data: Optional[AnyStr] = None,
                 is_binary: Optional[bool] = False) -> None:
        """Initiate the class."""

        self.tag = tag
        if not self.tag:
            self.tag = utilities.generate_message_tag()

        self.data = data
        self.is_binary = is_binary

    def serialize(self, keys: Sequence[bytes]) -> AnyStr:
        """Unserialize the message. A regular JSON message
        will be encoded. A binary message will be encrypted and also
        prefixed with an HMAC checksum. It returns a ready-to-send
        websocket message."""
        if not self.is_binary:
            return self.encode()
        return self.encrypt(keys)

    def encrypt(self, keys: Sequence[bytes]) -> bytes:
        """Encrypts a binary message."""
        enc_key, mac_key = keys
        checksum = crypto.hmac_sha256(mac_key, self.data)
        serialized = f"{self.tag},".encode()
        serialized += checksum
        serialized += crypto.aes_encrypt(enc_key, self.data)
        return serialized

    def encode(self) -> str:
        """JSON encode the message if the message is not a
        binary message."""
        encoded_message = f"{self.tag},{json.dumps(self.data)}"
        return encoded_message

    @classmethod
    def unserialize(cls, message: AnyStr,
                    keys: Sequence[bytes]) -> Union[WebsocketMessage, None]:
        """Process a message and decide whether it is a binary
        message or a regular JSON message. Then it will serialize
        the message according to its type."""
        if not isinstance(message, bytes):
            return cls.from_encoded(message)
        return cls.from_encrypted(message, keys)

    @classmethod
    def from_encoded(cls, message: str) -> WebsocketMessage:
        """Returns an initiated class from an encoded message."""
        tag, encoded_data = message.split(",", 1)
        return cls(tag, json.loads(encoded_data))

    @classmethod
    def from_encrypted(cls, message: bytes,
                       keys: Sequence[bytes]) -> Union[WebsocketMessage, None]:
        """Returns an initiated class from a binary message.
        This function also decrypts the contained message. """
        enc_key, mac_key = keys

        instance = cls()
        instance.is_binary = True

        tag, data = message.split(b",", 1)
        instance.tag = tag

        checksum = data[:32]
        encrypted_data = data[32:]

        if not (enc_key and mac_key):
            logging.info("dropping binary message with tag %s (no keys)", tag)
            return None

        if crypto.hmac_sha256(mac_key, encrypted_data) != checksum:
            raise exceptions.HMACValidationError

        instance.data = crypto.aes_decrypt(enc_key, encrypted_data)

        return instance


class WebsocketMessages:
    """This class acts as a container for `WebsocketMessage` instances.
    Allows an easy access to messages in queue. The messages are feed
    by `WebsocketClient` class."""
    messages = {}

    def add(self, tag: str, data: AnyStr):
        """Appends a message to the messages mapping."""
        self.messages[tag] = data

    def get(self, tag: str, timeout: Optional[int] = 10):
        """Gets a message with specified tag. If not currently
        present, it will wait until `timeout` reached. Raises
        asyncio.TimeoutError when timed out."""
        async def get_message():
            while tag not in self.messages:
                await asyncio.sleep(0)
            return self.messages.pop(tag)

        logger.debug("Getting message with tag %s", tag)

        return asyncio.wait_for(get_message(), timeout)


class WebsocketClient:
    """Acts as interface for websocket communication with WhatsApp's
    websocket server."""
    websocket: websockets.WebSocketClientProtocol = None
    kyros_session: Session = None
    messages: WebsocketMessages = WebsocketMessages()

    def __init__(self, message_handler: MessageHandler) -> None:
        """Initiate the class. Registers message handler."""
        self.handle_message = message_handler

    async def connect(self) -> None:
        """Connects to the websocket server. Starts message receiver or
        listener."""
        logger.debug("Connecting to ws server")
        self.websocket = await websockets.connect(
            constants.WEBSOCKET_URI, origin=constants.WEBSOCKET_ORIGIN, close_timeout=None, ping_interval=None)
        logger.debug("Websocket connected")
        self._start_receiver()

    async def keep_alive(self):
        if self.websocket and self.websocket.open:
            await self.websocket.send('?,,')
            # Send keepalive every 10 seconds
            Timer(10.0, self.keep_alive)

    def load_session(self, session: Session) -> None:
        """Loads a session. This will make sure that all references are
        updated. If there is a key change, the new key will be used to
        decrypt new messages."""
        self.kyros_session = session

    def get_keys(self) -> Sequence[bytes]:
        """Extract necessary keys from session to decrypt and encrypt
        binary messages. """
        return self.kyros_session.enc_key, self.kyros_session.mac_key

    async def shutdown(self) -> None:
        """Does a cleanup. Closes websocket connection."""
        if self.websocket.open:
            logger.debug("Closing websocket server")
            await self.websocket.close()

    def _start_receiver(self) -> None:
        """Starts a receiver coroutine. Listens for a new websocket message
        from queue."""
        async def receiver():
            while True:
                if not self.websocket or not self.websocket.open:
                    logger.debug("receiver returned: no ws/connection closed")
                    return

                if not self.websocket.messages or self.websocket.closed:
                    await asyncio.sleep(0)
                    continue

                raw_message = self.websocket.messages.pop()

                # Ignore server timestamp responses
                if raw_message[:1] == "!":
                    continue

                try:
                    message = WebsocketMessage.unserialize(
                        raw_message, self.get_keys())
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Ignored error decoding message: %s", exc)
                    await asyncio.sleep(0)
                    continue

                if message:
                    logger.debug("Received WS message with tag %s",
                                 message.tag)
                    self.messages.add(message.tag, message.data)

        asyncio.ensure_future(receiver())
        logger.debug("Executed receiver coroutine")

    async def send_message(self, message: WebsocketMessage) -> None:
        """Sends a websocket message."""
        logger.debug("Sending a WS message with tag %s", message.tag)
        await self.websocket.send(message.serialize(self.get_keys()))
