import json

from ECC import curve, Point
from hashlib import sha256
import socketio
import eventlet
from aiohttp import web
from abe_utils import verify2


# issuing and revoking users' attributes
# map GID to attribute list


class Key:
    __slots__ = 'master_key', 'public_key'
    pass


class Attribute:
    def __init__(self):
        self.list = ['doctor', 'nurse', 'engineers', 'greece', 'america']
        self.public_key = []
        self.k = []


class Message:
    def __init__(self, name, c0, c1, c2, p):
        self.name = name
        self.c0 = c0
        self.c1 = c1
        self.c2 = c2
        self.p = p

    def __repr__(self):
        return str({'c0': self.c0, 'c1': self.c1, 'c2': self.c2, 'p': self.p}) + f" from {self.name}\n"


key = Key()
attribute = Attribute()
users = {}
sids = {}
msgs = []

sio = socketio.AsyncServer(async_mode='aiohttp', cors_allowed_origins='*', logger=True, engineio_logger=True)
app = web.Application()
sio.attach(app)


def unpack(data):
    name = data['from']
    c0 = data['c0']
    c1 = data['c1']
    c2 = data['c2']
    p = data['p']
    return Message(name, c0, c1, c2, p)


def setup():
    key.master_key = curve.generatePrivateKey()
    key.public_key = curve.generatePublicKey(key.master_key)
    for i in range(0, len(attribute.list)):
        k = curve.generatePrivateKey()
        attribute.k.append(k)
        attribute.public_key.append(curve.generatePublicKey(k).compress())


@sio.event
def user_init(sid, data):
    name = data["name"]
    print(f"A user {name} wants to get attribute about ", end='')
    attributes = data["attributes"]
    for i, _attribute in enumerate(attributes):
        if _attribute:
            print(attribute.list[i], end=' ')
    # ans = input("accept?(y/n) ")
    ans = 'y'
    if ans == 'y':
        keys = []
        for i, _attribute in enumerate(attributes):
            if _attribute:
                k = attribute.k[i]
                h = int.from_bytes(sha256(name.encode('utf-8')).digest(), 'big')
                sk = k + h * key.master_key
                keys.append(sk)
            else:
                keys.append(-1)
        users[name] = keys
        print("success!")
        sids[name] = sid
        print(sid)


@sio.event
async def send(sid, data):
    if data['to'] in sids:
        await sio.emit('message',
                       {'from': data['from'], 'c0': data['c0'], 'c1': data['c1'], 'c2': data['c2'], 'p': data['p']},
                       room=sids[data['to']])


@sio.event
async def save(sid, data):
    message = unpack(data)
    msgs.append(message)
    print(msgs)
    print("save data success")


@sio.event
async def fetch(sid, data):
    attr_index = data['attr_index']
    for msg in msgs:
        if verify2(msg.c2, msg.p, attr_index):
            await sio.emit('message',
                           {'from': msg.name, 'c0': msg.c0, 'c1': msg.c1, 'c2': msg.c2, 'p': msg.p},
                           room=sid)
            print(f"fetch message success:\n {msg}\n")


@sio.event
async def decrypt(sid, data):
    name = data['name']
    c1 = data['c1']
    c2 = data['c2']
    p = data['p']
    sk = users[name]
    if verify2(c2, p, sk):
        res = Point((None, None), curve)
        for _p, _c2 in zip(p, c2):
            c2_point = Point(_c2, curve)
            sk_p = sk[attribute.list.index(_p)]
            res += sk_p * c2_point
        await sio.emit('decrypt', {'res': res.compress(), 'c1': data['c1'], 'c0': data['c0'], 'from': data['from']},
                       room=sid)
    else:
        await sio.emit('decrypt_fail', {'from': data['from']},
                       room=sid)


@sio.event
async def get_pk(sid):
    await sio.emit('handle_pk', {'pk': attribute.public_key}, room=sid)


if __name__ == '__main__':
    setup()
    HOST = '127.0.0.1'
    PORT = 10001
    web.run_app(app, host=HOST, port=PORT)
