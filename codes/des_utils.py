# -*- coding: utf-8 -*-

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad


class SymEncrypt(object):

    @staticmethod
    def get_des_encrypt(data: str, key: bytes, mode: str = None, iv: bytes = None) -> bytes:
        """
        返回DES加密后的数据信息;
        :param data: str; 被加密的明文信息;
        :param key: bytes; 密钥信息,长度通常是8位;
        :param mode: 加密模式,本模块暂时值封装常用的情况 ECB 和 CBC;
        :param iv: bytes; 当模式是 ECB 的时候默认是None,DES中常用的长度是8;
        :return: bytes; 返回加密后的字节数据;
        """
        # 处理两种不同的模式信息;
        if mode == "ECB":
            # 本模式之下不需要使用 iv 的随机向量值
            # 1.创建加密器
            des = DES.new(key=key, mode=DES.MODE_ECB)
            # 2.进行数据的填充,与字节转换;
            data = pad(data.encode(), 8)
            # 获取加密结果并返回
            result = des.encrypt(data)
            return result
        else:
            # 其他模式的情况下需要使用iv值,当前使用的是CBC模式,可以使用 eval()函数扩展其他模式;
            des = DES.new(key=key, mode=DES.MODE_CBC, IV=iv)
            data = pad(data.encode(), 8)
            result = des.encrypt(data)
            return result

    @staticmethod
    def get_des_decrypt(data: bytes, key: bytes, mode: str = None, iv: bytes = None) -> bytes:
        """
        返回DES解密后的数据信息;
        :param data: str; 被加密的密文信息;
        :param key: bytes; 密钥信息,长度通常是8位;
        :param mode: 加密模式,本模块暂时值封装常用的情况 ECB 和 CBC;
        :param iv: bytes; 当模式是 ECB 的时候默认是None,DES中常用的长度是8;
        :return: bytes; 返回加密后的字节数据;
        """
        # 处理两种不同的模式信息;
        if mode == "ECB":
            # 本模式之下不需要使用 iv 的随机向量值
            # 1.创建加密器
            des = DES.new(key=key, mode=DES.MODE_ECB)
            # 2.进行数据的填充,与字节转换;
            # 对数据进行解密
            data = des.decrypt(data)
            # 解密完成之后,将填充好的数据进行去除
            result = unpad(data, 8)
            return result
        else:
            # 其他模式的情况下需要使用iv值,当前使用的是CBC模式,可以使用 eval()函数扩展其他模式;
            des = DES.new(key=key, mode=DES.MODE_CBC, IV=iv)
            data = des.decrypt(data)
            # 先解密后去除填充;
            result = unpad(data, 8)
            return result


if __name__ == '__main__':
    v = SymEncrypt.get_des_encrypt("昨天吃多了", "abcdefgh".encode(), mode="CBC", iv=b"01234567")
    print(v)  # 加密
    import base64

    v = base64.b64encode(v)  # 进行 base64编码
    print(v.decode())  # bas64 可以编译成 字符串的形式
    # 进行base64解码
    sv = base64.b64decode(v.decode())
    ssv = SymEncrypt.get_des_decrypt(sv, key="abcdefgh".encode(), mode="CBC", iv=b"01234567")
    print(ssv)  # 解密完成
    print(ssv.decode())  # 字节的转换