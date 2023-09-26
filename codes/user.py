import time

import socketio
from ECC import curve, Point
from abe_utils import *

serverSocket = socketio.Client()
serverSocket.connect('http://127.0.0.1:10001')
attr_list = ['doctor', 'nurse', 'engineers', 'greece', 'america']
name = ""
attr_index = []
pk = []


def init():
    global name, attr_index
    attributes_str = input("attr = ")
    attributes = attributes_str.split(' ')
    attr_index = []
    for i in range(0, len(attr_list)):
        attr_index.append(False)
    for attribute in attributes:
        attr_index[attr_list.index(attribute)] = True

    name = input("name = ")
    serverSocket.emit('user_init', {'name': name, 'attributes': attr_index})


def parser_conditions(access_condition):
    conditions = access_condition.split(' ')
    postfix = make_postfix(conditions)
    root = make_tree(postfix)
    A, p = levelorder(root)
    return A, p

@serverSocket.event
def encrypt(data):
    public_keys = data['pk']
    access_condition = data['condition']
    msg = data['msg']
    A, p = parser_conditions(access_condition)
    pk = []
    for attr in p:
        key = public_keys[attr_list.index(attr)]
        pk.append(Point(key, curve))

    M = msg_tp_point(msg)
    s = curve.generatePrivateKey()
    c0 = M + s * curve.G
    l = len(A[0])
    lamb = []
    ome = []
    v = [s]
    u = [0]
    for j in range(1, l):
        v.append(curve.generatePrivateKey())
        u.append(curve.generatePrivateKey())
    for a in A:
        lamb.append(vector_mult(v, a))
        ome.append(vector_mult(u, a))

    c1 = []
    c2 = []
    for lam, om, _p in zip(lamb, ome, pk):
        c1.append((lam * curve.G + om * _p).compress())
        c2.append((om * curve.G).compress())
    return c0, c1, c2, p


@serverSocket.event
def message(data):
    cx = 1
    p = data['p']
    c2 = data['c2']
    c1 = data['c1']
    c0 = data['c0']
    res = verify1(c1, c2, p, attr_index)
    if res:
        serverSocket.emit('decrypt', {'name': name, 'c0': c0, 'c1': res[0], 'c2': res[1], 'p': res[2],
                                      'from': data['from']})
    else:
        decrypt_fail(data)


@serverSocket.event
def decrypt(data):
    sum_c1 = Point(None, None)
    c0 = data['c0']
    c1 = data['c1']
    res = data['res']
    res_point = Point(res, curve)
    for _c1 in c1:
        c1_point = Point(_c1, curve)
        sum_c1 += c1_point
    sg = sum_c1 - res_point
    c0_point = Point(c0, curve)
    m = c0_point - sg
    print("\nMsg from " + data['from'] + ' ' + point_to_msg(m) + '\n')


@serverSocket.event
def decrypt_fail(data):
    print(f"\n{data['from']} tried to send message to you but fail due to lack of attribute(s)...")


@serverSocket.event
def handle_pk(data):
    print(data)
    global pk
    pk = data['pk']
    return data


def save_msg():
    access_condition = input("Type condition(and, or): ")
    msg = input("msg: ")
    serverSocket.emit('get_pk')
    time.sleep(1)
    global pk
    data = {'pk': pk, 'condition': access_condition, 'msg': msg}
    c0, c1, c2, p = encrypt(data)
    serverSocket.emit('save', {'from': name, 'c0': c0.compress(), 'c1': c1, 'c2': c2, 'p': p})


def fetch_msg():
    data = {'attr_index': attr_index}
    serverSocket.emit('fetch', data)


def start():
    print("\n1: Save message, 2: Fetch message, 3: Exit")
    cmd = int(input("Cmd? "))
    if cmd == 1:
        save_msg()
    elif cmd == 2:
        fetch_msg()
    elif cmd == 3:
        return
    time.sleep(1)
    start()


if __name__ == '__main__':
    init()
    start()
