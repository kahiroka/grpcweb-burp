import struct
import binascii
import json

class ProtoBufs:
    @staticmethod
    def decode(msg):
        dic = {}
        lis = []
        if len(msg) > 0:
            idx = 0
            while True:
                if len(msg) < idx:
                    raise ValueError
                elif len(msg) == idx:
                    break
                var, width = ProtoBufs.devar(msg[idx:])
                key = var >> 3
                wire_type = var & 7
                idx = idx + width
                if wire_type == 0: # var/uint32
                    var, width = ProtoBufs.devar(msg[idx:])
                    dic[str(key) + ":var"] = var
                    idx = idx + width
                elif wire_type == 1: # i64/double
                    val = round(struct.unpack("<d", msg[idx:idx+8])[0], 3)
                    dic[str(key) + ":f64"] = val
                    idx = idx + 8
                elif wire_type == 2: # string/embedded
                    size, width = ProtoBufs.devar(msg[idx:])
                    tmp = msg[idx + width:idx + width + size]

                    if str(key) in dic:
                        if type(dic[str(key)]) == dict:
                            tmp2 = dic[str(key)]
                            lis.append(tmp2)
                            dic[str(key)] = lis
                        try:
                            if ProtoBufs.is_printable(tmp):
                                raise ValueError
                            dic[str(key)].append(ProtoBufs.decode(tmp))
                        except:
                            if ProtoBufs.is_printable(tmp):
                                dic[str(key)].append(tmp.decode())
                            else:
                                dic[str(key) + ":hex"].append(binascii.hexlify(tmp).decode())
                    else:
                        try:
                            if ProtoBufs.is_printable(tmp):
                                raise ValueError
                            dic[str(key)] = ProtoBufs.decode(tmp)
                        except:
                            if ProtoBufs.is_printable(tmp):
                                dic[str(key)] = tmp.decode()
                            else:
                                dic[str(key) + ":hex"] = binascii.hexlify(tmp).decode()

                    idx = idx + width + size
                elif wire_type == 5: # i32/float
                    val = round(struct.unpack("<f", msg[idx:idx+4])[0], 3)
                    dic[str(key) + ":f32"] = val
                    idx = idx + 4
                else:
                    #print("key:{} wire_type:{} something wrong".format(key, wire_type))
                    #print(msg[idx:])
                    raise ValueError
            return dic

    @staticmethod
    def encode(dic):
        if dic == None:
            return b''
        msg = b''
        for key in dic.keys():
            if type(dic[key]) == dict: # embedded
                emb = ProtoBufs.encode(dic[key])
                blen = ProtoBufs.envar(len(emb))
                msg = msg + ProtoBufs.envar((int(key)<<3 | 0x02)) + blen + emb
            elif type(dic[key]) == list: # embedded
                for item in dic[key]:
                    emb = ProtoBufs.encode(item)
                    blen = ProtoBufs.envar(len(emb))
                    msg = msg + ProtoBufs.envar((int(key)<<3 | 0x02)) + blen + emb
            elif "var" in key: # uint32
                msg = msg + ProtoBufs.envar((int(key.split(':')[0])<<3 | 0x00)) + ProtoBufs.envar(dic[key])
            elif "f32" in key: # i32
                msg = msg + ProtoBufs.envar((int(key.split(':')[0])<<3 | 0x05)) + struct.pack('<f', dic[key])
            elif "f64" in key: # i64
                msg = msg + ProtoBufs.envar((int(key.split(':')[0])<<3 | 0x01)) + struct.pack('<d', dic[key])
            elif "hex" in key: # hex
                unhex = binascii.unhexlify(dic[key])
                blen = ProtoBufs.envar(len(unhex))
                msg = msg + ProtoBufs.envar((int(key.split(':')[0])<<3 | 0x02)) + blen + unhex
            else: # string/bytes
                blen = ProtoBufs.envar(len(dic[key]))
                msg = msg + ProtoBufs.envar((int(key)<<3 | 0x02)) + blen + dic[key].encode("utf-8")
        return msg

    @staticmethod
    def devar(msg): # uint32
        var = 0
        idx = 0
        while True:
            var = (((msg[idx] if isinstance(msg[idx], int) else ord(msg[idx])) & 0x7f) << (idx*7)) | var
            idx = idx + 1
            if not ((msg[idx-1] if isinstance(msg[idx-1], int) else ord(msg[idx-1])) & 0x80):
                break
        return var, idx

    @staticmethod
    def envar(var): # uint32
        msg = b''
        for i in range(5):
            if var >> 7:
                msg = msg + struct.pack('B', (var & 0x7f | 0x80))
                var = var >> 7
            else:
                msg = msg + struct.pack('B', (var & 0x7f | 0x00))
                break
        return msg

    @staticmethod
    def is_printable(s):
        for char in s:
            #if 0x20 <= ord(char) <= 0x7E:
            val = char if isinstance(char, int) else ord(char)
            if 0x20 <= val <= 0x7E:
                continue
            #elif char in ('\n', '\r', '\t'):
            #    continue
            else:
                return False
        return True

def main():
    dic1 = {"1:var": 256, "256:var": 1, "2": {"1": [{"1": "john", "2:f32": 0.1}, {"1": "jane", "2:f32": 0.2}]}, "3:hex": "deadbeef"}
    print(dic1)
    msg1 = ProtoBufs.encode(dic1)
    print(msg1)
    dic2 = ProtoBufs.decode(msg1)
    print(dic2)
    print(json.dumps(dic2))

if __name__ == "__main__":
    main()
