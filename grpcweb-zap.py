import json
import struct
from protobufs import ProtoBufs # or inline here

def decode_grpcweb(msg):
    msg.getRequestHeader().setHeader("x-grpcweb-flag", "true")
    body = msg.getRequestBody().getBytes().tostring()
    decoded = json.dumps(ProtoBufs.decode(body[5:]))
    msg.setRequestBody(decoded)
    msg.getRequestHeader().setContentLength(len(decoded))

def encode_grpcweb(msg):
    msg.getRequestHeader().setHeader("x-grpcweb-flag", None)
    body = msg.getRequestBody().getBytes().tostring()
    encoded = ProtoBufs.encode(json.loads(body))
    grpcweb = struct.pack("B", 0x00) + struct.pack(">I", len(encoded)) + encoded
    msg.setRequestBody(grpcweb)
    msg.getRequestHeader().setContentLength(len(grpcweb))

def proxyRequest(msg):
    print('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
    header_value = msg.getRequestHeader().getHeader("content-type")
    if header_value and header_value.lower() == "application/grpc-web+proto":
        decode_grpcweb(msg)
    return True

def proxyResponse(msg):
    return True

def sendingRequest(msg, initiator, helper):
    print('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
    header_value = msg.getRequestHeader().getHeader("x-grpcweb-flag")
    if header_value and header_value.lower() == "true":
        encode_grpcweb(msg)

def responseReceived(msg, initiator, helper):
    pass
