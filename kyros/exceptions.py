class HMACValidationError(Exception):
    """Raised when checksum does not match. For example, when
    validating binary messages."""
    message = "checksum verification failed"


class StatusCodeError(Exception):
    """Raised when a websocket message responded with an unexpected
    status code."""
    def __init__(self, code):
        self.code = code
        message = f"Unexpected status code: {code}"
        super().__init__(message)
