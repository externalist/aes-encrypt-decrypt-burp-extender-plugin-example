# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from java.io import PrintWriter
import base64
from urlparse import parse_qs
import sys
import subprocess
import json


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks=callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AES encrypt/decrypt example")
        callbacks.registerMessageEditorTabFactory(self)
        return
        
    def createNewInstance(self, controller, editable):                
        return EncryptedInputTab(self, controller, editable)
        
class EncryptedInputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.editable = editable
        self.controller = controller
        self.helpers = extender.helpers
        self.httpHeaders = None
        self.content = None
        self.url = None
                
        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)
        return
        
    def getTabCaption(self):
        return "Encrypted Data viewer & editor"
        
    def getUiComponent(self):
        return self.txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        self.content = content

        if('server domain goes here' in self.controller.getHttpService().getHost()):
            if(isRequest):
                info = self.helpers.analyzeRequest(self.controller.getHttpService(), content)
                self.httpHeaders = info.getHeaders()
                self.url = info.getUrl()
                body = content[info.getBodyOffset():].tostring()
                parameter_dict = parse_qs(body)
                for parameter, value in parameter_dict.iteritems():
                    if parameter == 'inqTrcn':
                        return True
            else:
                info = self.helpers.analyzeResponse(content)
                self.httpHeaders = info.getHeaders()
                return True
        return False
    
    def isModified(self):        
        return self.txtInput.isTextModified()
    
    def getSelectedData(self):        
        return self.txtInput.getSelectedText()
        
    def setMessage(self, content, isRequest):
        self.txtInput.setText("")
        output = ""
        
        if content is None:
            self.editor.setText(None)
            self.editor.setEditable(False)
            return
        
        if isRequest:
            info = self.helpers.analyzeRequest(content)
        else:
            info = self.helpers.analyzeResponse(content)
  
        headers = info.getHeaders()
        body = content[info.getBodyOffset():].tostring()
        
        if isRequest:
            parameter_dict = parse_qs(body)
            for parameter, value in parameter_dict.iteritems():
                if parameter == 'inqTrcn':
                    proc = subprocess.Popen(['python','C:/Tools/BurpSuite/decrypt.py',value[0]],stdout=subprocess.PIPE)
                    output = proc.stdout.read()
                    proc.stdout.close()
        else:
            json_data = json.loads(body)
            encrypted = json_data['rsltCtt'][0]['RSLT_CTT']
            proc = subprocess.Popen(['python','C:/Tools/BurpSuite/decrypt.py',encrypted],stdout=subprocess.PIPE)
            output = proc.stdout.read().decode('utf-8').encode('euc-kr').strip()
            proc.stdout.close()

        self.txtInput.setText(self.extender.helpers.stringToBytes(output))
        return

    def getMessage(self):
        if(self.txtInput.isTextModified()):
            edit_text = self.extender.helpers.bytesToString(self.txtInput.getText())
            proc = subprocess.Popen(['python','C:/Tools/BurpSuite/encrypt.py', edit_text],stdout=subprocess.PIPE)
            output = proc.stdout.read()
            proc.stdout.close()
            request_string = "inqTrcnFieldae=testyo&inqTrcn=" + output
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, request_string)
        else:
            return self.content