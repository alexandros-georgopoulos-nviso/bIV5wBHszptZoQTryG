from java.io import (
    Serializable,
    File,
    FileWriter,
    IOException,
    FileOutputStream,
    ObjectOutputStream,
)
from java.nio.file import Files, StandardCopyOption
from java.util import ArrayList
from javax import swing
from static import Static
from utils import read_file
import string
import re
import tempfile
import os
from evidence import Evidence
import utils
import sys
import base64


class Project(Serializable):
    """Project holds all the Finding objects in an ArrayList - The findings hold the Evidence objects"""

    def __init__(self):
        self.findings = ArrayList()
        self.rules = ArrayList()

        self.autoSaveProject = False
        self.location = ""
        self.prefix = ""

        self.notesFileName = "info"
        self.evidenceFileName = "evidence"

        self.ressources_path = os.path.join(sys.path[4], "burp_finding_template")

        self.notesFindingTemplate = (
            "INFO - %NAME%\n"
            "%LINE%\n\n\n"
            "Supporting evidences:\n"
            "----------------------\n"
        )

        self.notesEvidenceTemplate = "- %NAME%:\n" + "		Description: %DETAILS%\n\n"
        self.httpReqRespTemplate = (
            "REQUEST\n"
            + "-" * 8
            + "\n"
            + "%REQUEST%\n\n"
            + "RESPONSE\n"
            + "-" * 8
            + "\n"
            + "%RESPONSE%\n"
        )

    def read_editable_file_content(self):
        for f in self.findings:
            for e in f.evidences:
                print(e.filePath, e.evidenceType)
                if e.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                    print(e.filePath)
                    e.content = read_file(e.filePath)
                    print(e.content)

    def setFindings(self, findings):
        self.findings = findings

    def setRules(self, rules):
        self.rules = rules

    def addFinding(self, finding):
        """A new Finding was created"""
        self.findings.add(finding)

        if self.autoSaveProject:
            self.autoSaveFinding(finding)

    # def print_evidences(self):
    #     # print('PRIIINNNTTTINNGGG')
    #     for f in self.findings:
    #         for e in f.evidences:
    #             print(e.messageInfo, e.name, e.details, e.evidenceType, e.filePath, e.content)

    def addEvidence(self, finding, evidence):
        """A new Evidence was created"""
        index = self.findings.indexOf(finding)
        self.findings.get(index).addEvidenceToFinding(evidence)

        # recovery, will save a copy in temp folder, independantly of if autosave is selected or not
        self.serializeProject(True)

        if self.autoSaveProject:
            self.autoSaveNotes(finding, finding.getNotes())
            self.autoSaveEvidence(finding, evidence)
            self.serializeProject()

    def load_text_file(self):
        for f in self.findings:
            for e in f.evidences:
                pass

    def addNotesToFinding(
        self, finding, evidence, append, findingTemplateName="default"
    ):
        """A finding or an evidence is added. Add the notes according to the template.
        If append == TRUE --> Finding else it is an Evidence
        Append means an evidence is added and not a finding
        When append is set to True, the findingTemplateName value is not important. But when
        the append is set to False, a new finding is created from the specified template.
        The default template is provided with the plugin, but the other must be created as files
        on the system.
        """
        if not append:  # Finding
            if findingTemplateName == "default":
                template = self.notesFindingTemplate
            else:
                try:
                    template = read_file(self.ressources_path + findingTemplateName)
                except:
                    Static.showWarning(
                        "Warning!",
                        "The selected template could not be found on the system. Please create it or try another template.",
                    )
                    return

            if "%NAME%" in template:
                result = string.replace(template, "%NAME%", finding.name)
                template = result

            if "%SEVERITY%" in template:
                result = string.replace(template, "%SEVERITY%", finding.severity)
                template = result
            if "%LINE%" in template:
                # print(len(str(finding.name)) + len('INFO - '))
                result = string.replace(
                    template, "%LINE%", "-" * (len(template.partition("\n")[0]))
                )
                template = result

            # Add the template to the finding

            finding.addNotesToFinding(template)

        else:  # Evidence
            template = self.notesEvidenceTemplate

            if "%NAME%" in template:
                result = string.replace(template, "%NAME%", evidence.name)
                template = result

            if "%DETAILS%" in template:
                result = string.replace(template, "%DETAILS%", evidence.details)
                template = result

            if "%HOST%" in template:
                result = string.replace(
                    template, "%HOST%", evidence.httpReqResp.getHttpService().getHost()
                )
                template = result

            if "%PORT%" in template:
                result = string.replace(
                    template, "%PORT%", evidence.httpReqResp.getHttpService().getPort()
                )
                template = result

            if "%PROTOCOL%" in template:
                result = string.replace(
                    template,
                    "%PROTOCOL%",
                    evidence.httpReqResp.getHttpService().getProtocol(),
                )
                template = result

            # Add the template to the finding
            finding.addNotesToFinding(finding.getNotes() + "\n" + template)

    def saveNotes(self, finding, notes):
        """notes should be converted to string before they are received"""
        i = self.findings.indexOf(finding)
        self.findings.get(i).evidences.get(0).notes = notes

        if self.autoSaveProject:
            self.autoSaveNotes(finding, notes)
            self.serializeProject()

    def saveHttpReqResp(self, finding, evidence, request, response, extender):
        """requests and responses are received as a byte array"""
        f = self.findings.indexOf(finding)
        e = self.findings.get(f).evidences.indexOf(evidence)
        b64_eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
        clear_eicar = base64.b64decode(b64_eicar).decode("utf-8")
        eicar_replacement = "< EICAR VIRUS TEST FILE >"

        # Process only if some evidences were found
        if len(self.findings.get(f).evidences) != 1:
            if evidence != None:
                if evidence.evidenceType == Evidence.REQ_RESPONSE_FILE:
                    # Remove EICAR string automatically
                    cleanreq = extender.helpers.bytesToString(request).replace(
                        clear_eicar, eicar_replacement
                    )
                    cleanreq = extender.helpers.stringToBytes(cleanreq)

                    cleanresp = extender.helpers.bytesToString(response).replace(
                        clear_eicar, eicar_replacement
                    )
                    cleanresp = extender.helpers.stringToBytes(cleanresp)

                    self.findings.get(f).evidences.get(e).httpReqResp.setRequest(
                        cleanreq
                    )
                    self.findings.get(f).evidences.get(e).httpReqResp.setResponse(
                        cleanresp
                    )

                if self.autoSaveProject:
                    self.autoSaveHttpReqResp(finding, evidence)
                    self.serializeProject()

    def saveEditableTextFile(self, finding, evidence, content):
        if evidence.evidenceType == Evidence.EDITABLE_TEXT_FILE:
            f = self.findings.indexOf(finding)
            e = self.findings.get(f).evidences.indexOf(evidence)
            self.findings.get(f).evidences.get(e).setContent(content)

        if evidence.evidenceType == Evidence.NON_EDITABLE_FILE:
            f = self.findings.indexOf(finding)
            e = self.findings.get(f).evidences.indexOf(evidence)
            self.findings.get(f).evidences.get(e).setContent(content)
            if evidence.isTextBased():
                utils.write_text_file(
                    evidence.filePath, self.findings.get(f).evidences.get(e).content
                )

        if self.autoSaveProject:
            self.autoSaveEditableTextFile(finding, evidence)
            self.serializeProject()

    def autoSaveEditableTextFile(self, finding, evidence):
        index = self.findings.indexOf(finding)
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name
        fileName = dirFinding + File.separator + evidence.name + ".txt"
        # Check if the directory exists, otherwise recreate it (maybe user renamed it manually)
        if not File(dirFinding).exists():
            self.recreateFinding(finding)
            return

        writer = None
        try:
            # Create and write the file, overwrite if necessary
            utils.write_text_file(fileName, evidence.content)
        except Exception as e:
            # print(e)
            # print('okk')
            print(
                "Oops",
                "Something went wrong when writing the Evidence file with AutoSave ON",
            )

            if writer:
                writer.close()

    def changeFindingName(self, finding, name, extender):
        i = self.findings.indexOf(finding)
        original = self.findings.get(i).name

        self.findings.get(i).name = name
        modified = self.findings.get(i).name

        # Automatically update finding name in notes
        self.findings.get(i).addNotesToFinding(
            self.findings.get(i).getNotes().replace(original, modified, 1)
        )
        # Display updated notes
        extender.textArea.setText(self.findings.get(i).getNotes())

        # if self.autoSaveProject:
        if self.location != "":
            # AutoRename the directory
            uid = self.prefix + str(i + 1).zfill(2)  # A01, A02, ...
            src = File(self.location + File.separator + uid + " - " + original)
            dst = File(self.location + File.separator + uid + " - " + modified)

            # if src does not exist, recreate
            if not src.exists():
                self.recreateFinding(finding)

            try:
                Files.move(
                    src.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING
                )
            except IOException as e:
                print(e)

            self.serializeProject()

    def changeEvidenceName(self, finding, evidence, name):
        f = self.findings.indexOf(finding)
        e = self.findings.get(f).evidences.indexOf(evidence)
        original = self.findings.get(f).evidences.get(e).name + ".txt"

        self.findings.get(f).evidences.get(e).name = name
        modified = self.findings.get(f).evidences.get(e).name + ".txt"

        if self.autoSaveProject:
            # AutoRename the evidence file
            uid = self.prefix + str(f + 1).zfill(2)  # A01, A02, ...
            dirFinding = self.location + File.separator + uid + " - " + finding.name

            src = File(dirFinding + File.separator + original)
            dst = File(dirFinding + File.separator + modified)

            # if evidence does not exists, create
            if not src.exists():
                self.autoSaveHttpReqResp(finding, evidence)
                self.serializeProject()
                return

            try:
                Files.move(
                    src.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING
                )
            except IOException as e:
                print(e)

            self.serializeProject()

    def removeFinding(self, index):
        finding = self.findings.get(index)
        self.findings.remove(index)

        if self.autoSaveProject:
            self.autoRemoveFinding(index, finding)
            self.serializeProject()

    def removeEvidence(self, indexFinding, indexEvidence):
        finding = self.findings.get(indexFinding)
        evidence = self.findings.get(indexFinding).evidences.get(indexEvidence)
        self.findings.get(indexFinding).removeEvidence(indexEvidence)
        # self.findings.get(indexFinding).evidences.remove(indexEvidence)

        if self.autoSaveProject:
            self.autoRemoveEvidence(indexFinding, finding, evidence)
            self.serializeProject()

    def autoSaveFinding(self, finding):
        # Create the finding directory which will hold the evidence files
        i = self.findings.indexOf(finding)
        uid = self.prefix + str(i + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name

        File(dirFinding).mkdirs()

    def autoSaveEvidence(self, finding, evidence):
        if not (evidence.name == self.notesFileName):
            self.autoSaveHttpReqResp(finding, evidence)

    def autoSaveNotes(self, finding, notes):
        index = self.findings.indexOf(finding)
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name
        fileName = dirFinding + File.separator + self.notesFileName + ".txt"

        # Check if the directory exists, otherwise recreate it (maybe user renamed it manually)
        if not File(dirFinding).exists():
            self.recreateFinding(finding)
            return

        writer = None
        try:
            writer = FileWriter(fileName, False)
            writer.write(notes)
            writer.close()
        except Exception as e:
            # print(e)
            Static.showWarning(
                "Oops",
                "Something went wrong when writing the notes file with AutoSave ON",
            )

            if writer:
                writer.close()

    def autoSaveHttpReqResp(self, finding, evidence):

        if evidence.messageInfo is None:  # the evidence has no ReqResp and is a file!
            return

        index = self.findings.indexOf(finding)
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name
        fileName = dirFinding + File.separator + evidence.name + ".txt"

        # Check if the directory exists, otherwise recreate it (maybe user renamed it manually)
        if not File(dirFinding).exists():
            self.recreateFinding(finding)
            return

        request = evidence.getRequestAsString()
        response = evidence.getResponseAsString()

        # Check if any rules exist to snip certain headers
        if len(self.rules) > 0:
            for rule in self.rules:
                if rule.enabled:
                    request, response = self.snipHeaders(rule, request, response)

        template = self.httpReqRespTemplate

        if "%REQUEST%" in template:
            result = string.replace(template, "%REQUEST%", request)
            template = result

        if "%RESPONSE%" in template:
            result = string.replace(template, "%RESPONSE%", response)
            template = result

        writer = None
        try:
            # Create and write the file, overwrite if necessary
            writer = FileWriter(fileName, False)
            writer.write(template)
            writer.close()
        except Exception as e:
            # print(e)
            Static.showWarning(
                "Oops",
                "Something went wrong when writing the Evidence file with AutoSave ON",
            )

            if writer:
                writer.close()

    def autoRemoveFinding(self, index, finding):
        # AutoRemove the finding directory
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name

        # Check if the directory exists, otherwise leave (maybe user renamed it manually)
        if not File(dirFinding).exists():
            return

        # Delete the finding dir and everything left in it (like screenshots or other files)
        Static.recurseRemove(File(dirFinding))

        # For all the findings after the deleted finding, change the folder names
        # if you make a sublist i will be 0. index is the i of the deleted finding e.g. A03
        for i, f in enumerate(self.findings.subList(index, len(self.findings))):
            uidOld = self.prefix + str(index + 2 + i).zfill(2)  # A04, A05, ...
            uidNew = self.prefix + str(index + 1 + i).zfill(2)  # A03, A04, ...
            src = File(self.location + File.separator + uidOld + " - " + f.name)
            dst = File(self.location + File.separator + uidNew + " - " + f.name)

            try:
                Files.move(
                    src.toPath(), dst.toPath(), StandardCopyOption.REPLACE_EXISTING
                )
            except IOException as e:
                Static.showError(
                    "Oops!",
                    "Something went wrong in autoRemoveFinding when trying to rename the folders "
                    "to have correct UID's."
                    "\nCheck the output/error tabs for more info",
                )
                print(e.getMessage())
                return

    def autoRemoveEvidence(self, index, finding, evidence):
        # AutoRemove the evidence file
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name
        fileName = dirFinding + File.separator + evidence.name + ".txt"

        # Check if the finding directory exists or evidence file, otherwise leave (maybe user renamed it manually)
        if not File(dirFinding).exists() or not File(fileName).exists():
            return

        File(fileName).delete()

    def snipHeaders(self, rule, request, response):
        """This method will replace the values of the header in the Request and Response specified by the rule"""

        # Find and snip the values of the headers using regex
        needle = rule.nameHeader
        haystack = request
        request = re.sub(
            r"{}:.*".format(needle), "{}: < SNIP >".format(needle), haystack
        )

        # Some requests don't have responses, e.g. from Repeater
        if response:
            needle = rule.nameHeader
            haystack = response
            response = re.sub(
                r"{}:.*".format(needle), "{}: < SNIP >".format(needle), haystack
            )

        return request, response

    def serializeProject(self, recovery=False):
        """Serialize the project and write it to evidences.ser"""
        try:
            # if recovery is True, location will be temporary folder
            location = tempfile.gettempdir() if recovery else self.location
            serializedProject = File(location + File.separator + "evidences.ser")
            outFile = FileOutputStream(serializedProject)
            outStream = ObjectOutputStream(outFile)
            # autoSave is put to False because we don't want this option to be enabled when someone loads it back
            autoSaveValue = self.autoSaveProject
            self.autoSaveProject = False
            outStream.writeObject(self)
            outFile.close()
            self.autoSaveProject = autoSaveValue
            return True

        except IOException as e:
            # onlye show the exception if autosave is on and the error is not a result of the recovery mechanism
            if not recovery:
                Static.showError(
                    "Oops!",
                    "An error occurred when AutoSerializing the project: "
                    "\nCheck the output/error tabs for more info"
                    "\n\nYou should try to disable the autoSave option",
                )
                print(e.getMessage())
            return False

    def recreateFinding(self, finding):
        # When AutoSave is ON but it cannot find the directory to save (because a user has manually changed the dirname)
        index = self.findings.indexOf(finding)
        uid = self.prefix + str(index + 1).zfill(2)  # A01, A02, ...
        dirFinding = self.location + File.separator + uid + " - " + finding.name

        File(dirFinding).mkdirs()
        self.autoSaveNotes(finding, finding.getNotes())

        # for every evidence file except notes
        for index in range(1, len(finding.evidences)):
            self.autoSaveHttpReqResp(finding, finding.evidences[index])

    def updateNotesFileName(self, name):
        # Update finding name
        if name != self.notesFileName:
            self.notesFileName = name

            for finding in self.findings:
                finding.evidences.get(0).setName(name)

    def updateEvidencesFileName(self, name):
        # Update EvidenceFiles name
        if name != self.evidenceFileName:
            self.evidenceFileName = name

            for finding in self.findings:
                for e in range(1, len(finding.evidences)):
                    # Update evidence file name except for the FIRST ONE --> first one is notes
                    finding.evidences.get(e).setName(name + str(e).zfill(2))

    def equals(self, project):
        if project:
            return (
                self.autoSaveProject == project.autoSaveProject
                and self.location.replace(File.separator, "/")
                == project.location.replace(File.separator, "/")
                and self.prefix == project.prefix
                and self.findings.equals(project.findings)
            )

        return False
