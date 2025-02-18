from burp import IHttpRequestResponse, IHttpService
from java.io import Serializable


class HttpRequestResponse(Serializable, IHttpRequestResponse):
    """ By default HttpRequestResponse is not Serializable
    this class is needed to have the ability to save serialized objects"""

    comment = None
    highlight = None
    httpService = None
    request = None
    response = None

    def __init__(self, httpReqResp):
        self.comment = httpReqResp.comment
        self.highlight = httpReqResp.highlight
        self.request = httpReqResp.request
        self.response = httpReqResp.response
        self.httpService = httpReqResp.httpService

    def setHttpService(self, httpService):
        self.httpService = httpService

    def getComment(self):
        return self.comment

    def getHighlight(self):
        return self.highlight

    def getHttpService(self):
        return self.httpService

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response

    def getRequestAsString(self):
        """self.request is an array. Convert the array to a string and return it
        Can't use Burp helpers here because the class needs to be serializable"""

        # Make sure the request only contains printable characters
        clean_request = [x if 0 < x < 256 else 0 for x in self.request]

        return "".join(map(chr, clean_request))

    def getResponseAsString(self):
        """self.response is an array. Convert the array to a string and return it
        Can't use Burp helpers here because the class needs to be serializable"""

        if self.response:
            # Make sure the request only contains printable characters
            clean_response = [x if 0 < x < 256 else 0 for x in self.response]

            return "".join(map(chr, clean_response))
        else:
            return ""

    def setComment(self, comment):
        self.comment = comment

    def setHighlight(self, highlight):
        self.highlight = highlight

    def setRequest(self, message):
        self.request = message

    def setResponse(self, message):
        self.response = message

    def equals(self, httpReqResp):
        if httpReqResp:
            return self.comment == httpReqResp.comment and self.highlight == httpReqResp.highlight \
                   and self.request == httpReqResp.request and self.response == httpReqResp.response \
                   and self.httpService.equals(httpReqResp.httpService)

        return False


class HttpService(Serializable, IHttpService):
    """ By default httpService is not Serializable,
    this class is needed to have the ability to save serialized objects"""
    host = None
    port = None
    protocol = None

    def __init__(self, httpService):
        self.host = httpService.getHost()
        self.port = httpService.getPort()
        self.protocol = httpService.getProtocol()

    def getHost(self):
        return self.host

    def getPort(self):
        return self.port

    def getProtocol(self):
        return self.protocol

    def equals(self, httpService):
        if httpService:
            return self.host == httpService.host and self.port == httpService.port \
                   and self.protocol == httpService.protocol

        return False
