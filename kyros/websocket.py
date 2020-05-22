import asyncio
import concurrent.futures
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

    async def get(self, tag, timeout=10):
        cancel_event = asyncio.Event()

        def get_message():
            while tag not in self.messages:
                if cancel_event.is_set():
                    return None
            return self.messages[tag]

        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(None, get_message)
        logger.debug("Getting message with tag %s (in executor)", tag)

        try:
            return await asyncio.wait_for(future, timeout)
        except concurrent.futures.TimeoutError:
            pass
        finally:
            cancel_event.set()

        raise TimeoutError


class WebsocketClient:
    websocket = None
    messages = WebsocketMessages()
    receiver_future = None
    cancel_event = asyncio.Event()

    def __init__(self, message_handler):
        self.handle_message = message_handler

    async def connect(self):
        logger.debug("Connecting to ws server")
        self.websocket = await websockets.connect(
            constants.WEBSOCKET_URI, origin=constants.WEBSOCKET_ORIGIN)
        logger.debug("Websocket connected")

    async def start_receiving(self):
        def receiver():
            while True:
                if self.cancel_event.is_set():
                    return
                if not self.websocket.messages:
                    continue
                raw_message = self.websocket.messages.pop()
                try:
                    message = WebsocketMessage.from_encoded(raw_message)
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("Ignored error decoding message: %s", exc)
                    continue
                logger.debug("Received WS message with tag %s", message.tag)
                self.messages.add(message.tag, message.data)

        loop = asyncio.get_event_loop()
        self.receiver_future = loop.run_in_executor(None, receiver)
        logger.debug("Executed receiver func in executor")

    async def stop_receiving(self):
        if self.receiver_future:
            self.cancel_event.set()
            asyncio.ensure_future(self.receiver_future)
            logger.debug("Stopped websocket receiver")
        return

    async def send_message(self, message: WebsocketMessage):
        logger.debug("Sending a WS message with tag %s", message.tag)
        await self.websocket.send(message.encode())
