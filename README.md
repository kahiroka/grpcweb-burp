# gRPC-Web Burp Extension
Burp Suite Extension for gRPC-Web with Protocol Buffers

## Burp Suite
Install 'Jython standalone' and add grpcweb-burp.py as a Python extension in the Extensions tab. Right-click on the message in the Proxy tab and select Sent to Intruder or Sent to Repeater from Extensions->gRPC-Web.　gRPC-Web is decoded and displayed as an intermediate JSON representation, and encoded and sent as gRPC-Web.

## ZAP (Experimental)
Install 'Python Scripting' and add grpcweb-zap.py to HTTP Sender and Proxy.