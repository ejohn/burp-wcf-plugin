import sys
import base64
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
import subprocess
from subprocess import CalledProcessError
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # set our extension name
        callbacks.setExtensionName("WCF Binary Decoder")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        return
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return Base64InputTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class Base64InputTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._controller = controller

        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "WCF Binary Decoded"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):

        self._isRequest = isRequest
        # enable this tab for requests containing the msbin1 content type
        if self._controller == None:
            return False

        try:
            
            self._requestBytes = self._controller.getRequest()

            if not isRequest:
                self._responseBytes = self._controller.getResponse()
                return WCFBinaryHelper.IsTargetRequest(self._extender, self._responseBytes)    

            return WCFBinaryHelper.IsTargetRequest(self._extender, self._requestBytes)
            

        except:
            self._extender.stdout.println("Unexpected error isEnabled: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))
            return False
        
        
        
    def setMessage(self, content, isRequest):

        try:

            if (content is None):
                # clear our display
                self._txtInput.setText(None)
                self._txtInput.setEditable(False)
            
            else:

                if self._isRequest:
                    data = self._requestBytes
                else:
                    data = self._responseBytes

                if data != None:
                    request_info = self._extender._helpers.analyzeRequest(data)
                    bodyOffset = request_info.getBodyOffset()

                    body_bytes = list(data)[bodyOffset:]
                    wcf_decoded = WCFBinaryHelper.DecodeWCF(self._extender, self._extender._helpers.base64Encode(self._extender._helpers.bytesToString(body_bytes)))


                    self._txtInput.setText(self._extender._helpers.base64Decode(wcf_decoded))
                    self._txtInput.setEditable(self._editable)
            return
        except:
            self._extender.stdout.println("Unexpected error setMessage: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))

        finally:
            # remember the displayed content
            self._currentMessage = content
        
    
    def getMessage(self):
        try:
            # determine whether the user modified the deserialized data
            if (self._txtInput.isTextModified()):
                # reserialize the data
                text = self._txtInput.getText()

                request_info = self._extender._helpers.analyzeRequest(self._requestBytes)
                headers = request_info.getHeaders()

                wcf_encoded = WCFBinaryHelper.EncodeWCF(self._extender, text)

                return self._extender._helpers.buildHttpMessage(headers, wcf_encoded)

            else:
                return self._currentMessage
        except:
            self._extender.stdout.println("Unexpected error getMessage: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))
        
    
    def isModified(self):

        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        
        return self._txtInput.getSelectedText()
            


class WCFBinaryHelper:

    @classmethod
    def GetHeadersContaining(cls, findValue, headers):
        if(findValue!=None and headers!=None and len(headers)>0):
            return [s for s in headers if findValue in s]
        return None
    
    @classmethod
    def IsTargetRequest(cls, extender, request_bytes):
        try:
            if request_bytes == None: 
                return False

            request_info = extender._helpers.analyzeRequest(request_bytes)
            if request_info == None: 
                extender.stdout.println("IsTargetRequest: False2")
                return False
            headers = request_info.getHeaders()
            if(headers!=None and len(headers)>0):
                matched_headers = cls.GetHeadersContaining('Content-Type',headers)
                if(matched_headers!=None):
                    for matched_header in matched_headers:
                        if('msbin1' in matched_header):
                            return True

            return False
        except:
            extender.stdout.println("Unexpected error IsTargetRequest: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))


    @classmethod
    def DecodeWCF(cls, extender, base64EncodedBody):      
        try:
            proc = subprocess.Popen(['mono','nbfs.exe','decode',base64EncodedBody],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            extender.stdout.println(proc.stderr.read())
            return output

        except CalledProcessError, e:
            extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            extender.stdout.println("Unexpected error DecodeWCF: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))        
        return None
     
    @classmethod
    def EncodeWCF(cls,extender, xmlContent):       
        base64EncodedXML=base64.b64encode(xmlContent)

        try:
            proc = subprocess.Popen(['mono','nbfs.exe','encode',base64EncodedXML],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            #proc.wait()
            output = proc.stdout.read()
            #extender.stdout.println(output)
            extender.stdout.println(proc.stderr.read())
            return extender._helpers.stringToBytes(base64.b64decode(output))

        except CalledProcessError, e:
            extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
        except:
            extender.stdout.println("Unexpected error EncodeWCF: %s: %s\n%s" % (sys.exc_info()[0],sys.exc_info()[1],sys.exc_info()[2]))
        return None