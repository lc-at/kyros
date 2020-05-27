class HMACValidationError(Exception):
    message = "validation failed"


class LoginError(Exception):
    pass


class StatusCodeError(Exception):
    def __init__(self, code):
        self.code = code
        message = f'Unexpected status code: {code}'
        super().__init__(message)
