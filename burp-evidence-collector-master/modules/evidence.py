from modules.utils import read_file
from java.io import Serializable

from serializable import HttpRequestResponse


class Evidence(Serializable):
    """Evidence class which can hold the notes or the different Requests/Responses"""

    notes = None
    name = None
    details = None
    filePath = None
    content = None
    httpReqResp = None
    backUpHttpReqResp = None
    messageInfo = None
    evidenceType = 2
    filePathExtraFile = None

    NON_EDITABLE_FILE = 0
    EDITABLE_TEXT_FILE = 1
    REQ_RESPONSE_FILE = 2

    def __init__(self, messageInfo, name, detailsReqResp, evidenceType, filePath, content, filePathExtraFile):
        self.notes = ""
        self.name = name
        self.filePath = filePath
        self.filePathExtraFile = filePathExtraFile
        self.content = content
        self.messageInfo = None
        self.details = detailsReqResp
        self.evidenceType = evidenceType
        if messageInfo:
            self.messageInfo = messageInfo
            self.httpReqResp = messageInfo
            self.backUpHttpReqResp = HttpRequestResponse(messageInfo)

    def setName(self, name):
        self.name = name

    def setDetails(self, details):
        self.details = details

    def setEvidenceType(self, evidenceType):
        self.evidenceType = evidenceType

    # Used when saving/exporting
    def getRequestAsString(self):
        return self.httpReqResp.getRequestAsString()

    def getResponseAsString(self):
        return self.httpReqResp.getResponseAsString()

    def setContent(self, content):
        self.content = content.tostring().replace("\r", "")

    def isTextBased(self):
        # inspired by this stackoverflow answer https://stackoverflow.com/questions/898669/how-can-i-detect-if-a-file-is-binary-non-text-in-python
        # which replicates the behaviour of the file utility
        
        with open(self.filePath, 'rb') as f:
            return not bool(f.read(1024).translate(None, bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})))

    def equals(self, evidence):
        if evidence:
            # Determine if it's the notes or request/response
            if not evidence.httpReqResp:
                return self.notes == evidence.notes and self.name == evidence.name and self.details == evidence.details

            return (
                self.name == evidence.name
                and self.details == evidence.details
                and self.httpReqResp.equals(evidence.httpReqResp)
                and self.backUpHttpReqResp.equals(evidence.backUpHttpReqResp)
            )

        return False
