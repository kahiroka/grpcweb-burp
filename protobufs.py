import struct
import binascii
import json

class ProtoBufError(Exception):
    """Base exception for protobuf parsing errors"""
    pass

class InvalidWireTypeError(ProtoBufError):
    """Raised when an invalid wire type is encountered"""
    pass

class MessageTooLargeError(ProtoBufError):
    """Raised when message exceeds size limits"""
    pass

class MalformedMessageError(ProtoBufError):
    """Raised when message structure is invalid"""
    pass

class ProtoBufs:
    # Security limits
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_NESTING_DEPTH = 100
    MAX_FIELD_KEY = 536870911  # 2^29 - 1 (protobuf max field number)
    
    @staticmethod
    def decode(msg, depth=0):
        # Input validation
        if msg is None:
            raise MalformedMessageError("Message cannot be None")
        
        if not isinstance(msg, (bytes, bytearray)):
            raise MalformedMessageError("Message must be bytes or bytearray")
        
        # Size validation
        if len(msg) > ProtoBufs.MAX_MESSAGE_SIZE:
            raise MessageTooLargeError("Message exceeds maximum size limit")
        
        # Depth validation to prevent stack overflow
        if depth > ProtoBufs.MAX_NESTING_DEPTH:
            raise MalformedMessageError("Message nesting too deep")
        
        dic = {}
        lis = []
        if len(msg) > 0:
            idx = 0
            while True:
                # Bounds checking
                if idx >= len(msg):
                    break
                if idx < 0:
                    raise MalformedMessageError("Invalid message index")
                
                # Ensure we have enough bytes for varint
                if idx >= len(msg):
                    raise MalformedMessageError("Truncated varint in message")
                
                try:
                    var, width = ProtoBufs.devar(msg[idx:])
                except (IndexError, ValueError) as e:
                    raise MalformedMessageError("Failed to decode varint: " + str(e))
                
                # Validate field key
                key = var >> 3
                if key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(key))
                if key == 0:
                    raise MalformedMessageError("Invalid field key: 0")
                
                wire_type = var & 7
                idx = idx + width
                
                # Bounds check after consuming varint
                if idx > len(msg):
                    raise MalformedMessageError("Message truncated after field header")
                if wire_type == 0: # var/uint32
                    if idx >= len(msg):
                        raise MalformedMessageError("Insufficient bytes for varint")
                    try:
                        var, width = ProtoBufs.devar(msg[idx:])
                    except (IndexError, ValueError) as e:
                        raise MalformedMessageError("Failed to decode varint value: " + str(e))
                    dic[str(key) + ":var"] = var
                    idx = idx + width
                elif wire_type == 1: # i64/double
                    if idx + 8 > len(msg):
                        raise MalformedMessageError("Insufficient bytes for 64-bit value")
                    try:
                        val = round(struct.unpack("<d", msg[idx:idx+8])[0], 3)
                        dic[str(key) + ":f64"] = val
                    except struct.error as e:
                        raise MalformedMessageError("Failed to decode 64-bit value: " + str(e))
                    idx = idx + 8
                elif wire_type == 2: # string/embedded
                    if idx >= len(msg):
                        raise MalformedMessageError("Insufficient bytes for length-delimited field")
                    try:
                        size, width = ProtoBufs.devar(msg[idx:])
                    except (IndexError, ValueError) as e:
                        raise MalformedMessageError("Failed to decode length: " + str(e))
                    
                    # Validate size bounds
                    if size > ProtoBufs.MAX_MESSAGE_SIZE:
                        raise MessageTooLargeError("Field size exceeds limit: " + str(size))
                    if idx + width + size > len(msg):
                        raise MalformedMessageError("Field extends beyond message boundary")
                    
                    tmp = msg[idx + width:idx + width + size]

                    if str(key) in dic:
                        if type(dic[str(key)]) == dict:
                            tmp2 = dic[str(key)]
                            lis.append(tmp2)
                            dic[str(key)] = lis
                        try:
                            if ProtoBufs.is_printable(tmp):
                                raise ValueError
                            dic[str(key)].append(ProtoBufs.decode(tmp, depth + 1))
                        except (ProtoBufError, ValueError):
                            if ProtoBufs.is_printable(tmp):
                                try:
                                    dic[str(key)].append(tmp.decode('utf-8'))
                                except UnicodeDecodeError:
                                    dic[str(key) + ":hex"].append(binascii.hexlify(tmp).decode())
                            else:
                                dic[str(key) + ":hex"].append(binascii.hexlify(tmp).decode())
                    else:
                        try:
                            if ProtoBufs.is_printable(tmp):
                                raise ValueError
                            dic[str(key)] = ProtoBufs.decode(tmp, depth + 1)
                        except (ProtoBufError, ValueError):
                            if ProtoBufs.is_printable(tmp):
                                try:
                                    dic[str(key)] = tmp.decode('utf-8')
                                except UnicodeDecodeError:
                                    dic[str(key) + ":hex"] = binascii.hexlify(tmp).decode()
                            else:
                                dic[str(key) + ":hex"] = binascii.hexlify(tmp).decode()

                    idx = idx + width + size
                elif wire_type == 5: # i32/float
                    if idx + 4 > len(msg):
                        raise MalformedMessageError("Insufficient bytes for 32-bit value")
                    try:
                        val = round(struct.unpack("<f", msg[idx:idx+4])[0], 3)
                        dic[str(key) + ":f32"] = val
                    except struct.error as e:
                        raise MalformedMessageError("Failed to decode 32-bit value: " + str(e))
                    idx = idx + 4
                else:
                    raise InvalidWireTypeError("Unsupported wire type: " + str(wire_type) + " for field: " + str(key))
            return dic

    @staticmethod
    def encode(dic):
        if dic is None:
            return b''
        
        # Input validation
        if not isinstance(dic, dict):
            raise MalformedMessageError("Input must be a dictionary")
        
        msg = b''
        total_size = 0
        
        for key in dic.keys():
            # Size check to prevent memory exhaustion
            total_size += len(str(dic[key]))
            if total_size > ProtoBufs.MAX_MESSAGE_SIZE:
                raise MessageTooLargeError("Encoded message would exceed size limit")
            
            if type(dic[key]) == dict: # embedded
                emb = ProtoBufs.encode(dic[key])
                blen = ProtoBufs.envar(len(emb))
                field_key = int(key)
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x02)) + blen + emb
            elif type(dic[key]) == list: # embedded
                for item in dic[key]:
                    emb = ProtoBufs.encode(item)
                    blen = ProtoBufs.envar(len(emb))
                    field_key = int(key)
                    if field_key > ProtoBufs.MAX_FIELD_KEY:
                        raise MalformedMessageError("Field key too large: " + str(field_key))
                    msg = msg + ProtoBufs.envar((field_key<<3 | 0x02)) + blen + emb
            elif "var" in key: # uint32
                field_key = int(key.split(':')[0])
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x00)) + ProtoBufs.envar(dic[key])
            elif "f32" in key: # i32
                field_key = int(key.split(':')[0])
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x05)) + struct.pack('<f', dic[key])
            elif "f64" in key: # i64
                field_key = int(key.split(':')[0])
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x01)) + struct.pack('<d', dic[key])
            elif "hex" in key: # hex
                try:
                    unhex = binascii.unhexlify(dic[key])
                except (binascii.Error, TypeError) as e:
                    raise MalformedMessageError("Invalid hex data: " + str(e))
                blen = ProtoBufs.envar(len(unhex))
                field_key = int(key.split(':')[0])
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x02)) + blen + unhex
            else: # string/bytes
                try:
                    encoded_str = dic[key].encode("utf-8")
                except (AttributeError, UnicodeEncodeError) as e:
                    raise MalformedMessageError("Failed to encode string: " + str(e))
                blen = ProtoBufs.envar(len(encoded_str))
                field_key = int(key)
                if field_key > ProtoBufs.MAX_FIELD_KEY:
                    raise MalformedMessageError("Field key too large: " + str(field_key))
                msg = msg + ProtoBufs.envar((field_key<<3 | 0x02)) + blen + encoded_str
        return msg

    @staticmethod
    def devar(msg): # uint32
        if not msg:
            raise MalformedMessageError("Empty message for varint decoding")
        
        var = 0
        idx = 0
        MAX_VARINT_BYTES = 10  # Maximum bytes for a varint (64-bit)
        
        while idx < len(msg) and idx < MAX_VARINT_BYTES:
            byte_val = msg[idx] if isinstance(msg[idx], int) else ord(msg[idx])
            var = ((byte_val & 0x7f) << (idx*7)) | var
            idx = idx + 1
            
            # Check for overflow
            if var > 0xFFFFFFFFFFFFFFFF:  # 64-bit max
                raise MalformedMessageError("Varint overflow")
            
            if not ((byte_val) & 0x80):
                break
        else:
            if idx >= MAX_VARINT_BYTES:
                raise MalformedMessageError("Varint too long")
            if idx >= len(msg):
                raise MalformedMessageError("Truncated varint")
        
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
