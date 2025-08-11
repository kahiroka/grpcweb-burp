from burp import IBurpExtender, IHttpListener, IContextMenuFactory
from java.awt.event import ActionListener
from javax.swing import JMenuItem
import json
from protobufs import ProtoBufs
import binascii
import struct

class RequestModifier:
    def __init__(self, helpers):
        self.helpers = helpers

    def grpcweb_decode(self, request_bytes):
        request_info = self.helpers.analyzeRequest(request_bytes)
        headers = list(request_info.getHeaders())
        body_bytes = request_bytes[request_info.getBodyOffset():]
        
        # Add header to encode later
        headers.append("X-GRPCWEB-FLAG: True")

        decoded = ProtoBufs.decode(body_bytes[5:].tostring())
        modified_bytes = self.helpers.stringToBytes(str(json.dumps(decoded)))

        # Reconstruct request
        modified_request = self.helpers.buildHttpMessage(headers, modified_bytes)
        return modified_request

    def grpcweb_encode(self, request_bytes):
        request_info = self.helpers.analyzeRequest(request_bytes)
        headers = list(request_info.getHeaders())
        body_bytes = request_bytes[request_info.getBodyOffset():]
        body = self.helpers.bytesToString(body_bytes)
        
        # Check if it is necessary
        if not "X-GRPCWEB-FLAG: True" in headers:
            return request_bytes
        else:
            headers.remove("X-GRPCWEB-FLAG: True")
        
        encoded = ProtoBufs.encode(json.loads(body))
        modified_bytes = struct.pack("B", 0x00) + struct.pack(">I", len(encoded)) + encoded
        #print(binascii.hexlify(modified_bytes))

        # Reconstruct request
        modified_request = self.helpers.buildHttpMessage(headers, modified_bytes)
        return modified_request

class CustomIntruderMenuHandler(ActionListener):
    def __init__(self, callbacks, request_modifier, invocation):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.request_modifier = request_modifier
        self.invocation = invocation
    
    def actionPerformed(self, event):
        try:
            # Get the selected request
            selected_messages = self.invocation.getSelectedMessages()
            if not selected_messages or len(selected_messages) == 0:
                return
            
            request_response = selected_messages[0]
            original_request = request_response.getRequest()
            
            # Decode the request
            modified_request = self.request_modifier.grpcweb_decode(original_request)
            
            # Send the modified request to Intruder
            self.callbacks.sendToIntruder(
                request_response.getHttpService().getHost(),
                request_response.getHttpService().getPort(),
                request_response.getHttpService().getProtocol() == "https",
                modified_request
            )
            print("Sent to Intruder")
            
        except Exception as e:
            print("Error at Send to Intruder: " + str(e))

class CustomRepeaterMenuHandler(ActionListener):
    def __init__(self, callbacks, request_modifier, invocation):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.request_modifier = request_modifier
        self.invocation = invocation
    
    def actionPerformed(self, event):
        try:
            # Get the selected request
            selected_messages = self.invocation.getSelectedMessages()
            if not selected_messages or len(selected_messages) == 0:
                return
            
            request_response = selected_messages[0]
            original_request = request_response.getRequest()
            
            # Decode the request
            modified_request = self.request_modifier.grpcweb_decode(original_request)
            
            # Send the modified request to Repeater
            self.callbacks.sendToRepeater(
                request_response.getHttpService().getHost(),
                request_response.getHttpService().getPort(),
                request_response.getHttpService().getProtocol() == "https",
                modified_request,
                "gRPC-Web"
            )
            print("Sent to Repeater")
            
        except Exception as e:
            print("Error at Send to Repeater: " + str(e))

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("gRPC-Web")
        
        # Initialize request modifier
        self.request_modifier = RequestModifier(self.helpers)
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Track modified requests to avoid infinite loops
        self.processed_requests = set()
        
        print("gRPC-Web extension loaded")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process requests, not responses
        if not messageIsRequest:
            return
        
        # Get the request
        request = messageInfo.getRequest()
        request_hash = hash(self.helpers.bytesToString(request))
        
        # Avoid infinite loops by tracking processed requests
        if request_hash in self.processed_requests:
            return
        
        # Check if the request is coming from a tool we want to modify
        if toolFlag == self.callbacks.TOOL_INTRUDER or toolFlag == self.callbacks.TOOL_REPEATER:
            print("processHttpMessage")
            try:
                # Encode the request
                modified_request = self.request_modifier.grpcweb_encode(request)
                
                # Update the request in the message info
                messageInfo.setRequest(modified_request)
            except Exception as e:
                print("Error processing request: " + str(e))
            return
    
    def createMenuItems(self, invocation):
        # Only show menu for requests in Proxy or Target tools
        if invocation.getInvocationContext() in [invocation.CONTEXT_PROXY_HISTORY, 
                                                invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                                                invocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            # Check if we have selected messages
            selected_messages = invocation.getSelectedMessages()
            if selected_messages and len(selected_messages) > 0:
                menu_item1 = JMenuItem("Send to Intruder")
                menu_item1.addActionListener(CustomIntruderMenuHandler(self.callbacks, self.request_modifier, invocation))
                menu_item2 = JMenuItem("Send to Repeater")
                menu_item2.addActionListener(CustomRepeaterMenuHandler(self.callbacks, self.request_modifier, invocation))
                return [menu_item1, menu_item2]
        
        return []