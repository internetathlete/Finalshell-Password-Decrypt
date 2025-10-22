import base64
import hashlib
import struct
from typing import Optional

try:
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import unpad
except Exception:
    # 允许先导入失败，后续通过安装依赖解决
    DES = None
    unpad = None


def _signed_byte(b: int) -> int:
    return struct.unpack('b', bytes([b & 0xFF]))[0]


class JavaRandom:
    """Python实现的java.util.Random，保证与Java一致的输出"""
    __mask = (1 << 48) - 1

    def __init__(self, seed: int):
        # Java的Random构造函数：seed = (seed ^ 0x5DEECE66D) & ((1<<48)-1)
        # 关键点：Java的long是64位二补码，这里先限制到64位再做初始扰动
        seed &= (1 << 64) - 1
        self.seed = ((seed ^ 0x5DEECE66D) & self.__mask)

    def next(self, bits: int) -> int:
        self.seed = (self.seed * 0x5DEECE66D + 0xB) & self.__mask
        return self.seed >> (48 - bits)

    def nextInt(self, n: int) -> int:
        if n <= 0:
            raise ValueError('n must be positive')
        # 若n为2的幂，走快速路径
        if (n & -n) == n:
            return (n * self.next(31)) >> 31
        while True:
            bits = self.next(31)
            val = bits % n
            if bits - val + (n - 1) >= 0:
                return val

    def nextLong(self) -> int:
        # 与Java一致的64位带符号long输出（严格模拟Java的long行为）
        hi = self.next(32)
        lo = self.next(32)
        # Java的实现是 ((long)hi << 32) + lo，其中 lo 是 32位有符号int
        # 当 lo 的第31位为1（即 lo >= 2^31）时，作为有符号int要减去 2^32
        if lo >= (1 << 31):
            lo -= (1 << 32)
        x = (hi << 32) + lo
        # 约束到 Java long 的取值范围（64位二补码）
        x &= (1 << 64) - 1
        return int.from_bytes(x.to_bytes(8, 'big', signed=False), 'big', signed=True)


def _random_key_from_head(head: bytes) -> bytes:
    # ks = 3680984568597093857L / new Random((long)head[5]).nextInt(127)
    r1 = JavaRandom(int(_signed_byte(head[5])))
    n127 = r1.nextInt(127)
    if n127 == 0:
        # Java会抛ArithmeticException，这里抛出同类异常信息
        raise ZeroDivisionError('random nextInt(127) returned 0, division by zero')
    ks = 3680984568597093857 // n127

    random = JavaRandom(int(ks))
    t = int(_signed_byte(head[0]))
    for _ in range(t if t > 0 else 0):
        _ = random.nextLong()

    n = random.nextLong()
    r2 = JavaRandom(int(n))

    ld = [
        int(_signed_byte(head[4])),
        int(r2.nextLong()),
        int(_signed_byte(head[7])),
        int(_signed_byte(head[3])),
        int(r2.nextLong()),
        int(_signed_byte(head[1])),
        int(random.nextLong()),
        int(_signed_byte(head[2])),
    ]
    # DataOutputStream.writeLong 为大端序有符号64位
    buf = bytearray()
    for l in ld:
        buf.extend(struct.pack('>q', l))

    digest = hashlib.md5(bytes(buf)).digest()
    return digest  # 16字节，Java DESKeySpec会取前8字节


def des_decode_payload(payload: bytes, head: bytes) -> bytes:
    if DES is None:
        raise RuntimeError('Crypto library (pycryptodome) is not installed')
    key16 = _random_key_from_head(head)
    key8 = key16[:8]
    cipher = DES.new(key8, DES.MODE_ECB)
    pt = cipher.decrypt(payload)
    # Java默认DES/ECB/PKCS5Padding，与PKCS7兼容，块长8
    try:
        pt = unpad(pt, 8)
    except Exception:
        # 若填充异常，直接返回原始解密数据，避免硬失败
        pass
    return pt


def decode_pass(b64data: str, encoding: str = 'utf-8') -> str:
    if not b64data:
        return ''
    raw = base64.b64decode(b64data)
    if len(raw) < 9:
        raise ValueError('decoded data too short')
    head = raw[:8]
    payload = raw[8:]
    pt = des_decode_payload(payload, head)
    try:
        return pt.decode(encoding)
    except Exception:
        return pt.decode(encoding, errors='replace')


__all__ = ['decode_pass']