import asyncio
import json
import logging

import websockets

from . import constants, utilities

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WebsocketMessage:
    def __init__(self, tag=None, data=None):
        self.tag = tag
        if not self.tag:
            self.tag = utilities.generate_message_tag()
        self.data = data

    def encode(self):
        encoded_message = f"{self.tag},{json.dumps(self.data)}"
        return encoded_message

    @classmethod
    def from_encoded(cls, encoded_message):
        tag, json_obj = encoded_message.split(",", 1)
        return cls(tag, json.loads(json_obj))


class WebsocketMessages:
    messages = {}

    def add(self, tag, data):
        self.messages[tag] = data

    def get(self, tag, timeout=10):
        async def get_message():
            while tag not in self.messages:
                await asyncio.sleep(0)
            return self.messages[tag]

        logger.debug("Getting message with tag %s (in executor)", tag)

        return asyncio.wait_for(get_message(), timeout)


class WebsocketClient:
    websocket = None
    messages = WebsocketMessages()

    def __init__(self, message_handler):
        self.handle_message = message_handler

    async def connect(self):
        logger.debug("Connecting to ws server")
        self.websocket = await websockets.connect(
            constants.WEBSOCKET_URI, origin=constants.WEBSOCKET_ORIGIN)
        logger.debug("Websocket connected")
        self._start_receiver()

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
                    message = WebsocketMessage.from_encoded(raw_message)
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
