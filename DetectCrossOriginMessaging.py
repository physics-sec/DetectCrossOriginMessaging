# -*- coding: utf-8 -*-

# Burp DetectCrossOriginMessaging Extension
# This extension is supposed to help find usages of postMessage and recvMessage
# which can lead to XSS and information leak

from burp import IBurpExtender
from burp import IExtensionStateListener
from burp import IHttpRequestResponse
from burp import IScannerCheck
from burp import IScanIssue
from array import array

GREP_STRINGS = [
    ".postMessage(",
    ".postMessage (",
    ".addEventListener(\"message\"",
    ".addEventListener('message'",
    ".addEventListener( \"message\"",
    ".addEventListener( 'message'",
    "add(window, \"message\"",
    "add(window,\"message\"",
    "add(window, 'message'",
    "add(window,'message'",
    "addListener(window, \"message\"",
    "addListener(window,\"message\"",
    "addListener(window, 'message'",
    "addListener(window,'message'"
    ]

GREP_STRINGS_BYTES = []
for g_str in GREP_STRINGS:
    GREP_STRINGS_BYTES.append( bytearray( g_str ) )

class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener, IHttpRequestResponse):

    def registerExtenderCallbacks(self, callbacks):

        print "Loading..."

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Detect cross origin messaging")
        callbacks.registerExtensionStateListener(self)
        callbacks.registerScannerCheck(self)

        print "Loaded detect cross origin messaging!"
        return

    def extensionUnloaded(self):
        print "Unloaded"
        return

    def _get_matches(self, response, matches):
        results = []
        reslen = len(response)
        for match in matches:
            start = 0
            matchlen = len(match)
            while start < reslen:
                start = self._helpers.indexOf(response, match, True, start, reslen)
                if start == -1:
                    break
                results.append(array('i', [start, start + matchlen]))
                start += matchlen

        return results

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def doPassiveScan(self, baseRequestResponse):
        matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRINGS_BYTES)
        if (len(matches) == 0):
            return None

        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "Cross origin mesagging detected",
            "Using postMessage or recvMessage can lead to XSS or information leak if used carelessly. It should be further investigated",
            "Information")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
