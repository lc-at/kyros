import logging
from .bin_reader import read_binary
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class MessageHandler:

    def __init__(self, on_message=None) -> None:
        """Initialize the message handler setting the callback function"""
        self.on_message = on_message

    def handle_message(self, message):
        """Decode binary message"""
        if message.data != "":
            try:
                msg_data = read_binary(message.data, True)
                if self.on_message is not None:
                    self.on_message(msg_data)

                """Message must be identified by type to call related handler"""            

                logger.debug("Received message: %s", msg_data)
            except Exception as exc:
                logger.error(
                    "There were an exception error processing received message: %s", str(exc))
        else:
            logger.error("Unknown empty message: %s", message)

    def handle_text_message(self):
        pass

    def handle_image_message(self):
        pass

    def handle_video_message(self):
        pass

    def handle_json_message(self):
        pass
