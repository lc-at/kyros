import asyncio

import pyqrcode

import kyros


async def main():
    whatsapp = await kyros.Whatsapp.create()
    qr_data, timeout = await whatsapp.qr_login()
    qr = pyqrcode.create(qr_data)
    print(qr.terminal(quiet_zone=1))
    await timeout


asyncio.get_event_loop().run_until_complete(main())
