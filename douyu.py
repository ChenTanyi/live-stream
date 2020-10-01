#!/usr/bin/env python3
import os
import re
import sys
import time
import uuid
import random
import typing
import hashlib
import logging
import requests
import threading
import websocket


def random_hex(length: int) -> str:
    return f'{random.getrandbits(length * 4):0{length}x}'


class Douyu():

    def __init__(self, url: typing.Union[str, int], player = 'potplayer'):
        if type(url) == int:
            self._rid = str(url)
        else:
            self._rid = self.extra_rid(url)
            if not self._rid:
                logging.error(f'Unable to extra room id from {url}')
                return
        self._session = requests.Session()
        vid = self.get_preview_vid()
        self.background_run(f'{player} {self.format_stream(vid)}')
        Danmaku(self._rid)

    @staticmethod
    def background_run(command: str):
        logging.info(command)
        thread = threading.Thread(target = os.system, args = (command,))
        thread.setDaemon(True)
        thread.start()

    @staticmethod
    def preview_api(rid: str) -> str:
        return f'https://playweb.douyucdn.cn/lapi/live/hlsH5Preview/{rid}'

    @staticmethod
    def extra_rid(url: str) -> str:
        match = re.match(
            r'^(?:(?:https?://)?(?:www.)?douyu.com/)?.*?(\d+)(\?.*)?$', url)
        if match:
            return match.group(1)

    @staticmethod
    def format_stream(vid: str) -> str:
        return f'http://tx2play1.douyucdn.cn/live/{vid}.flv'

    def get_preview_vid(self) -> str:
        cur_time = time.time_ns() // 1000000
        auth = hashlib.md5(f'{self._rid}{cur_time}'.encode()).hexdigest()
        resp = self._session.post(
            self.preview_api(self._rid),
            data = {
                'rid': self._rid,
                'did': random_hex(20)
            },
            headers = {
                'content-type': 'application/x-www-form-urlencoded',
                'rid': self._rid,
                'time': str(cur_time),
                'auth': auth,
            })
        resp.raise_for_status()
        resp: dict = resp.json()
        if resp.get('error') == 0:
            rtmp: str = resp.get('data', {}).get('rtmp_live')
            if rtmp:
                return re.match(r'^[^_/]*', rtmp).group()
            else:
                logging.error(f'Cannot get rtmp_live in response: {resp}')
        else:
            logging.error(resp)


def get_pre_url(rid):
    request_url = f'https://playweb.douyucdn.cn/lapi/live/hlsH5Preview/{rid}'
    post_data = {'rid': rid, 'did': f'{random.getrandbits(60):015x}'}
    auth = hashlib.md5(
        f'{rid}{int(time.time() * 1000)}'.encode('utf-8')).hexdigest()
    header = {
        'content-type': 'application/x-www-form-urlencoded',
        'rid': f'{rid}',
        'time': str(int(time.time() * 1000)),
        'auth': auth
    }
    response = requests.post(
        url = request_url, headers = header, data = post_data)
    print(response.content)


class Danmaku():

    def __init__(self, rid, server: str = 'wss://danmuproxy.douyu.com:8503/'):
        self._rid = rid
        self._server = server

        self._ws = websocket.WebSocketApp(
            'wss://danmuproxy.douyu.com:8503/',
            on_message = lambda *x: self.on_message(*x),
            on_error = lambda *x: self.on_error(*x),
            on_close = lambda *x: self.on_close(*x),
            on_open = lambda *x: self.on_open(*x))

        self.heartbeat_background()
        self._ws.run_forever()

    def on_message(self, ws, message):
        for msg in self._split_message(message):
            msg = self._deserialize_message(msg)
            if msg.get('type') == 'chatmsg':
                logging.info(f'[{msg.get("nn")}] {msg.get("txt")}')

    def on_error(self, ws, error):
        logging.error(error)

    def on_close(self, ws):
        logging.debug(f'close socket: {self._server}')

    def on_open(self, ws):
        logging.debug(f'open socket: {self._server}')
        self.login()
        self.join()

    def _send_message(self, msg):
        self._ws.send(self._format_message(msg))

    @staticmethod
    def _format_message(msg):
        length = len(msg) + 9
        msg_byte = msg.encode('utf-8')
        len_byte = length.to_bytes(4, 'little')
        return len_byte + len_byte + b'\xb1\x02\x00\x00' + msg_byte + b'\x00'

    def login(self):
        self._send_message(f'type@=loginreq/roomid@={self._rid}/')

    def join(self):
        self._send_message(f'type@=joingroup/rid@={self._rid}/gid@=-9999/')

    def heartbeat_background(self):
        event = threading.Event()
        t = threading.Thread(target = self.heartbeat, args = (event,))
        t.setDaemon(True)
        t.start()

    def heartbeat(self, event: threading.Event):
        while not event.wait(45):
            logging.debug("[Heart Beat]")
            self._send_message('type@=mrkl/')
            logging.debug("[Heart Beat] Done")

    def logout(self):
        self._send_message('type@=logout/')

    @staticmethod
    def _decode_message(msg: str) -> str:
        return msg.replace('@A', '@').replace('@S', '/')

    def _deserialize_message(self, msg: str) -> dict:
        pre_key = None
        msg_dict = dict()
        for message in msg.split('/'):
            if '@=' in message:
                key, value = message.split('@=')[:2]
                pre_key = self._decode_message(key)
                msg_dict[key] = self._decode_message(value)
            elif type(msg_dict[pre_key]) == list:
                msg_dict[pre_key].append(self._decode_message(message))
            else:
                msg_dict[pre_key] = [
                    msg_dict[pre_key],
                    self._decode_message(message)
                ]
        return msg_dict

    @staticmethod
    def _split_message(msg: bytes) -> typing.Iterator[str]:
        while msg:
            length = int.from_bytes(msg[:4], 'little')
            current_msg = msg[12:4 + length - 1]
            logging.debug(current_msg)
            msg = msg[4 + length:]

            yield current_msg.decode('utf-8')


if __name__ == "__main__":
    logging.basicConfig(
        level = logging.INFO,
        format = '%(asctime)s %(levelname)s %(message)s',
        datefmt = "%H:%M:%S")

    Douyu(sys.argv[1])