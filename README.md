# Kyros
Kyros, for now, is a Python interface to communicate easier with WhatsApp Web API.
It provides an interface to connect and communicate with WhatsApp Web's websocket server.
Kyros will handle encryption and decryption kind of things.
In the future, Kyros is aimed to provide a full implementation of WhatsApp Web API which will give developers
a clean interface to work with (more or less like [go-whatsapp](https://github.com/Rhymen/go-whatsapp)).
This module is designed to work with Python 3.6 or latest.
Special thanks to the creator of [whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng)
and [go-whatsapp](https://github.com/Rhymen/go-whatsapp). This project is largely motivated by their work.
Please note that Kyros is not meant to be used actively in production servers as it is currently not 
production ready. Use it at your own risk.

## Installation
Kyros could be installed by using `pip` or directly cloning it then invoking `setup.py`.
For example, if you want to use pip, run the following command:
```
pip install git+https://git@github.com/ttycelery/kyros
```

## Documentation
### A simple example
```python
import asyncio
import logging

import pyqrcode

from kyros import Client, WebsocketMessage

logging.basicConfig()
# set a logging level: just to know if something (bad?) happens
logging.getLogger("kyros").setLevel(logging.WARNING)

async def main():
    # create the Client instance using create class method
    whatsapp = await kyros.Client.create()
    
    # do a QR login
    qr_data, scanned = await whatsapp.qr_login()
    
    # generate qr code image
    qr_code = pyqrcode.create(qr_data)
    print(qr_code.terminal(quiet_zone=1))

    try:
        # wait for the QR code to be scanned
        await scanned
    except asyncio.TimeoutError:
        # timed out (left unscanned), do a shutdown
        await whatsapp.shutdown()
        return
    
    # how to send a websocket message
    message = kyros.WebsocketMessage(None, ["query", "exist", "1234@c.us"])
    await whatsapp.websocket.send_message(message)

    # receive a websocket message
    print(await whatsapp.websocket.messages.get(message.tag))


if __name__ == "__main__":
    asyncio.run(main())
```
A "much more detailed documentation" kind of thing for this project is available [here](https://ttycelery.github.io/kyros/).
You will see a piece of nightmare, happy exploring! Better documentation are being planned.

## Contribution
This work is still being slowly developed. Your contribution will of course
make the development process of this project even faster. Any kind of contribution
is highly appreciated.

## License
This project is licensed with MIT License.

## Disclaimer
This code is in no way affiliated with, authorized, maintained, sponsored
or endorsed by WhatsApp or any of its affiliates or subsidiaries. This is
an independent and unofficial software. Use at your own risk.
