import binascii
import builtins

def hex(b):
    if type(b) == list:
        ret = ""
        for c in b:
            ret += hex(c)
        return ret
    elif type(b) == int:
        ret = builtins.hex(b)[2:]
        if len(ret) == 1:
            return "0" + ret
        return ret
    else:
        return binascii.hexlify(b).decode("ascii")

