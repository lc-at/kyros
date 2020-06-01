# Kyros
Kyros, for now, is a Python interface to communicate easier with WhatsApp Web API.
It provides an interface to connect and communicate with WhatsApp Web's websocket server.
In the future, Kyros is aimed to provide a full implementation of WhatsApp Web API which will give developers
a clean interface to work with.
This module is designed to work with Python 3.6 or latest.
Special thanks to the creator of ![whatsapp-web-reveng](https://github.com/sigalor/whatsapp-web-reveng)
and ![go-whatsapp](https://github.com/Rhymen/go-whatsapp). This project is largely motivated by their work.
Please note that Kyros is not meant to be used actively in production servers as it is not production ready.
Use it at your own risk.

## Installation
Kyros could be installed by using `pip` or directly cloning it then invoking `setup.py`.
For example, if you want to use pip, run the following command:
```pip install git+https://git@github.com/ttycelery/kyros```

## Documentation
"Documentation" kind of thing for this project is available ![here](https://ttycelery.github.io/kyros/).

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


## To-do List
- Test: session restoration
- Test: read from an existing session
- Implementation of binary reader (encoder/decoder)
- A good exception/error handling in Kyros
- Reading messages
- Sending messages
- Handling messages
