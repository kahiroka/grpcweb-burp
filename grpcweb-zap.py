import json
from protobufs import ProtoBufs

def decode_grpcweb(msg):
    msg.getRequestHeader().setHeader("x-grpcweb-flag", "true")
    body = msg.getRequestBody()
    decoded = json.dumps(ProtoBufs.decode(body[5:]))
    msg.setRequestBody(decoded)
    msg.getRequestHeader().setContentLength(len(decoded))

def encode_grpcweb(msg):
    msg.getRequestHeader().removeHeader("x-grpcweb-flag")
    body = msg.getRequestBody().toString()
    encoded = ProtoBufs.encode(json.loads(body))
    msg.setRequestBody(encoded)
    msg.getRequestHeader().setContentLength(len(encoded))

def proxyRequest(msg):
    header_value = msg.getRequestHeader().getHeader("content-type")
    if header_value and header_value.lower() == "application/grpc-web+proto":
        decode_grpcweb(msg)
    return True

def sendingRequest(msg, initiator, helper):
    header_value = msg.getRequestHeader().getHeader("x-grpcweb-flag")
    if header_value and header_value.lower() == "true":
        encode_grpcweb(msg)

def responseReceived(msg, initiator, helper):
    pass
