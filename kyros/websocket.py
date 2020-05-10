import asyncio
import json
import threading

import websockets

from . import constants, utilities


class WebsocketMessage:
    def __init__(self, tag=None, data=None):
        self.tag = tag
        self.data = data

    def encode(self):
        if not self.tag:
            self.tag = utilities.generate_message_tag()
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
        async def get_message():
            while True:
                if tag not in self.messages:
                    continue
            return self.messages[tag]

        return asyncio.wait_for(get_message(), timeout)


class WebsocketClient:
    ws = None
    messages = WebsocketMessages()
    receiver_future = None
    cancel_event = threading.Event()

    async def connect(self):
        self.ws = await websockets.connect(constants.WEBSOCKET_URI,
                                           origin=constants.WEBSOCKET_ORIGIN)

    async def start_receiving(self):
        def receiver():
            while True:
                if self.cancel_event.is_set():
                    return
                raw_message = await self.ws.recv()
                message = WebsocketMessage.from_encoded(raw_message)
                self.messages.add(message.tag, message.data)

        loop = asyncio.get_event_loop()
        return loop.run_in_executor(None, receiver)

    async def stop_receiving(self):
        if self.receiver_future:
            self.cancel_event.set()
            await self.receiver_future
        return
