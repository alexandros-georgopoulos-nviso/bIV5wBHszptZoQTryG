from javax import swing
from java.awt import GridLayout, BorderLayout, Dimension, Color, Image, Toolkit
from java.awt.event import ActionListener, KeyEvent, KeyListener
from java.util import ArrayList, Collections
from java.io import (
    File,
    FileWriter,
    FileInputStream,
    FileOutputStream,
    ObjectOutputStream,
    IOException,
)
from java.nio.file import Files
from java.lang import Exception
from java.awt.datatransfer import DataFlavor
from misc import RequestHighlightTab, RequestFocusJComponent
from static import Static
from javax.imageio import ImageIO
from comparators import ComparatorSeverityArrayList
from java.awt.image import BufferedImage
import org.python.util as util
import string
import time
import re
import tempfile
import os.path
import shutil
import os
from os import listdir
from os.path import isfile, join
from evidence import Evidence
import utils


class HandleNewEditableTextEvidence(ActionListener):
    def __init__(self, extender):
        self.extender = extender
        self.evidenceName = None
        self.evidenceDescription = None
        self.iter = None

    def actionPerformed(self, e):
        modelRow = self.extender.tableModelFindings.getTable().getSelectedRow()
        if modelRow == -1:
            Static.showWarning(
                "Warning!", "Please select a Finding before adding an Evidence."
            )

        if self.extender.project.location == "":
            Static.showWarning(
                "Warning!", "Saving path must be set to use this functionality"
            )
            return False

        filePanel = swing.JPanel(GridLayout(2, 2))
        title = "Set editable text evidence name"
        filePanel.setBorder(swing.BorderFactory.createTitledBorder(title))
        evidenceNameLabel = swing.JLabel("Evidence name : ")
        evidenceDescriptionLabel = swing.JLabel("Evidence description : ")
        self.finding = self.extender.tableModelFindings.getTable().getValueAt(
            modelRow, 1
        )
        finding_obj = None
        self.iter = 0
        for i in self.extender.project.findings:
            if i.name == self.finding:
                finding_obj = i
                break
            self.iter += 1
        count = len(self.extender.project.findings.get(self.iter).evidences)

        self.evidenceName = swing.JTextField(
            self.extender.project.evidenceFileName + str(count).zfill(2)
        )
        self.evidenceDescription = swing.JTextField("[Editable text evidence]")
        filePanel.add(evidenceNameLabel)
        filePanel.add(self.evidenceName)
        filePanel.add(evidenceDescriptionLabel)
        filePanel.add(self.evidenceDescription)
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            filePanel,
            "New editable text evidence",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE,
        )
        if result != swing.JOptionPane.OK_OPTION:
            return False

        # FIXME : make sure the evidence name does not already exist.
        # FIXME : verify the saving path is set

        # TODO CREATE FILE

        # A01, A02, ...
        uid = self.extender.project.prefix + str(self.iter + 1).zfill(2)

        finding_dir = uid + " - " + self.finding
        evidence_file = self.evidenceName.getText() + ".txt"

        finding_path = os.path.join(self.extender.project.location, finding_dir)

        path = os.path.join(finding_path, evidence_file)

        if os.path.isdir(finding_path):
            utils.write_text_file(path, "")
        else:
            File(finding_path).mkdirs()
            utils.write_text_file(path, "")

        self.extender.tableModelEvidences.addEvidenceEntry(
            finding_obj,
            None,
            self.evidenceName.getText(),
            self.evidenceDescription.getText(),
            evidenceType=Evidence.EDITABLE_TEXT_FILE,
            filePath=path,
            filePathExtraFile="",
        )


class CombinedAction(ActionListener):
    def __init__(self, action1, action2):
        self.action1 = action1
        self.action2 = action2

    def actionPerformed(self, e):
        if self.action2 is not None:
            self.action2.pasting()


class HandleNewFileEvidence(ActionListener):
    """Responsible for adding an evidence file"""

    def __init__(self, extender):
        self.extender = extender
        self.filePathTextField = None
        self.iter = -1
        self.finding = ""
        self.newFilePath = ""

    def actionPerformed(self, e):
        if self.extender.project.location == "":
            Static.showWarning(
                "Warning!", "Saving path must be set to use this functionality"
            )
            return False

        modelRow = self.extender.tableModelFindings.getTable().getSelectedRow()
        if modelRow == -1:
            Static.showWarning(
                "Warning!", "Please select a Finding before adding an Evidence."
            )
        components = ArrayList()

        # Initialize some of the JComponents, only the ones from which we need the values

        fileDescriptionLabel = swing.JLabel("Description : ")
        self.fileDescriptionTextField = swing.JTextField()

        # txtNameFinding = swing.JTextField()
        filePathLabel = swing.JLabel("File path : ")
        self.filePathTextField = swing.JTextField()

        btnSelectFilePath = swing.JButton(
            "Select a file", actionPerformed=self.openFileDialog
        )
        ctrlVLabel = swing.JLabel("or use CTRL-V to paste.")
        filePanel = swing.JPanel(GridLayout(3, 3))
        title = "Select an evidence file."
        filePanel.setBorder(swing.BorderFactory.createTitledBorder(title))
        filePanel.add(filePathLabel)
        filePanel.add(self.filePathTextField)
        filePanel.add(btnSelectFilePath)
        filePanel.add(ctrlVLabel)
        filePanel.add(fileDescriptionLabel)
        filePanel.add(self.fileDescriptionTextField)

        ctrlV = swing.KeyStroke.getKeyStroke(KeyEvent.VK_V, KeyEvent.CTRL_DOWN_MASK)
        ctrlVAction = filePanel.getActionForKeyStroke(ctrlV)
        # filePanel.registerKeyboardAction(CombinedAction(ctrlVAction, CTRLVHandler(self)), ctrlV, swing.JComponent.WHEN_FOCUSED)
        filePanel.registerKeyboardAction(
            CombinedAction(ctrlVAction, self), ctrlV, swing.JComponent.WHEN_FOCUSED
        )
        self.filePathTextField.registerKeyboardAction(
            CombinedAction(ctrlVAction, self), ctrlV, swing.JComponent.WHEN_FOCUSED
        )
        components.add(filePanel)
        filePanel.addAncestorListener(RequestFocusJComponent(self.filePathTextField))
        # Show the customized OptionPane and save the result (ok/cancel)
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            components.toArray(),
            "What did you find?",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE,
        )

        # Check if user cancels the action
        if result != swing.JOptionPane.OK_OPTION:
            return False

        self.finding = self.extender.tableModelFindings.getTable().getValueAt(
            modelRow, 1
        )
        finding_obj = None

        # FIXME create function for this code
        self.iter = 0
        for i in self.extender.project.findings:
            if i.name == self.finding:
                finding_obj = i
                break
            self.iter += 1

        if os.path.isfile(self.filePathTextField.getText()):
            filepath = os.path.split(self.filePathTextField.getText())
            filename = filepath[1]

            if not filename:
                Static.showWarning(
                    "Warning!", "Please provide a filename that does not end in a slash"
                )
                return

            self.extender.tableModelEvidences.addEvidenceEntry(
                finding_obj,
                None,
                filename,
                self.fileDescriptionTextField.getText(),
                evidenceType=Evidence.NON_EDITABLE_FILE,
                filePath=self.filePathTextField.getText(),
                filePathExtraFile=self.filePathTextField.getText(),
            )
        else:
            Static.showWarning("Warning!", "The given file does not exists!")

    def pasting(self):
        self.getImageFromClipboard()

    def getImageFromClipboard(self):
        transferable = (
            Toolkit.getDefaultToolkit().getSystemClipboard().getContents(None)
        )

        if transferable != None and transferable.isDataFlavorSupported(
            DataFlavor.imageFlavor
        ):
            transferable.getTransferData(DataFlavor.imageFlavor)
            im = transferable.getTransferData(DataFlavor.imageFlavor)
            tempFile = Files.createTempFile(None, ".jpg")
            path = str(tempFile)
            ImageIO.write(im, "jpg", File(path))
            self.filePathTextField.setText(path)

    def openFileDialog(self, event):
        fileDialog = swing.JFileChooser()
        fileDialog.setDialogTitle("Select a file to import as evidence")
        ret = fileDialog.showSaveDialog(Static.getBurpFrame())
        if ret == swing.JFileChooser.APPROVE_OPTION:
            self.filePathTextField.setText(str(fileDialog.getSelectedFile()))


class HandleMenuItems(ActionListener):
    """This class is responsible for making the menuItems when the user right mouse clicks on a request.
    For example in the proxy tab or the repeater tab

    tip: MessageInfo is a serializable.HttpRequestResponse object"""

    def __init__(self, extender, messageInfo, createNew):
        self.extender = extender
        self.messageInfo = messageInfo
        self.createNew = createNew

    def actionPerformed(self, e):
        highlight = False
        if self.createNew:
            highlight = self.createNewFinding()
        else:
            highlight = self.addToFinding()

        if highlight:
            self.highlightTab()
            # select tabOverview if something has been added
            self.extender.getUiComponent().setSelectedIndex(0)

    def highlightTab(self):
        """Highlight the pane for 3 seconds in the Burp Suite orange color"""
        tabbedPane = self.extender.getUiComponent().getParent()
        collectorPane = self.extender.getUiComponent()

        if tabbedPane:
            for i in range(tabbedPane.getTabCount()):
                if tabbedPane.getComponentAt(i) == collectorPane:
                    tabbedPane.setBackgroundAt(i, Color(0xFF6633))

                    timer = swing.Timer(3000, RequestHighlightTab(self.extender))
                    timer.setRepeats(False)
                    timer.start()
                    break

    def createNewFinding(self):
        """Show an OptionPane with the different options to rate a new finding and describe the evidence file."""
        # ArrayList components holds all our JComponent objects
        components = ArrayList()

        # Initialize some of the JComponents, only the ones from which we need the values
        comboboxSeverity = swing.JComboBox(utils.risk_levels)
        txtNameFinding = swing.JTextField()
        txtNameEvidence = swing.JTextField()
        txtDescEvidence = swing.JTextField()

        # Set default values
        txtNameEvidence.setText(self.extender.project.evidenceFileName + "01")
        txtDescEvidence.setText("[Enter a description here]")

        # Create the finding panel
        findingPanel = swing.JPanel(GridLayout(2, 1))
        title = "Details finding :"
        findingPanel.setBorder(swing.BorderFactory.createTitledBorder(title))

        findingPanel.add(swing.JLabel("Severity"))
        findingPanel.add(comboboxSeverity)
        findingPanel.add(swing.JLabel("Name of the general finding : "))
        findingPanel.add(txtNameFinding)
        findingPanel.addAncestorListener(RequestFocusJComponent(txtNameFinding))

        # Create the evidence panel
        evidencePanel = swing.JPanel(GridLayout(3, 1))
        title = "Details evidence file:"
        evidencePanel.setBorder(swing.BorderFactory.createTitledBorder(title))

        evidencePanel.add(swing.JLabel("Name of the evidence file : "))
        evidencePanel.add(txtNameEvidence)
        evidencePanel.add(swing.JLabel("Details of the evidence file :"))
        evidencePanel.add(txtDescEvidence)

        templateFinding = swing.JComboBox(self.getFindingTemplateList())

        evidencePanel.add(swing.JLabel("Finding template : "))
        evidencePanel.add(templateFinding)

        # Add both parent JPanels (findingPanel,evidencePanel) to the components ArrayList
        components.add(findingPanel)
        components.add(evidencePanel)

        # Show the customized OptionPane and save the result (ok/cancel)
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            components.toArray(),
            "What did you find?",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE,
        )

        # Check if user cancels the action
        if result != swing.JOptionPane.OK_OPTION:
            return False

        # Get the values from the user and create a finding entry
        severity = comboboxSeverity.getSelectedItem()
        nameFinding = txtNameFinding.getText()
        nameEvidence = txtNameEvidence.getText()
        evidenceDetails = txtDescEvidence.getText()

        if nameFinding == "":
            Static.showWarning("Warning!", "The finding name cannot be empty!")
            return False

        if nameEvidence == "":
            Static.showWarning("Warning!", "The evidence name cannot be empty!")
            return False

        # If nameFinding or nameEvidence contain something NOT in the whitelist it is an invalid name
        for c in nameFinding:
            if c not in utils.whitelist:
                Static.showWarning("Warning!", "Invalid finding name!")
                return False

        for c in nameEvidence:
            if c not in utils.whitelist:
                Static.showWarning("Warning!", "Invalid evidence name!")
                return False

        self.extender.tableModelFindings.addFindingEntry(
            severity,
            nameFinding,
            self.messageInfo,
            nameEvidence,
            evidenceDetails,
            Evidence.REQ_RESPONSE_FILE,
            templateFinding.getSelectedItem(),
        )
        return True

    def getFindingTemplateList(self):
        try:
            template_files = [
                f
                for f in listdir(self.extender.project.ressources_path)
                if isfile(join(self.extender.project.ressources_path, f))
            ]
            template_files = ["default"] + template_files
            return template_files
        except:
            return ["default"]

    def addToFinding(self):
        # ArrayList components holds all our JComponent objects
        components = ArrayList()

        # Get all existing findings and show them in a combobox
        existingFindings = self.extender.project.findings

        if len(existingFindings) == 0:
            Static.showWarning("Warning!", "No findings found, add a finding first!")
            return False

        # For every entry in existingFindings make a new entry in comboboxArrayList with a different string format
        comboboxArrayList = ArrayList()
        for i in range(len(existingFindings)):
            comboboxArrayList.add(
                existingFindings[i].severity + " - " + existingFindings[i].name
            )

        # Initialize some of the JComponents, only the ones from which we need the values
        comboboxFindings = swing.JComboBox(comboboxArrayList)
        txtNameEvidence = swing.JTextField()
        txtDescEvidence = swing.JTextField()
        comboboxFindings.addActionListener(
            HandleChangeFindingCombobox(
                self.extender, comboboxFindings, txtNameEvidence
            )
        )
        comboboxFindings.setSelectedIndex(0)
        txtDescEvidence.setText("[Enter a description here]")

        # Create the finding panel
        findingPanel = swing.JPanel(GridLayout(1, 1))
        title = "All findings:"
        findingPanel.setBorder(swing.BorderFactory.createTitledBorder(title))

        findingPanel.add(swing.JLabel("Select a finding:"))
        findingPanel.add(comboboxFindings)

        # Create the evidence panel
        evidencePanel = swing.JPanel(GridLayout(4, 1))
        title = "Details evidence file:"
        evidencePanel.setBorder(swing.BorderFactory.createTitledBorder(title))

        evidencePanel.add(swing.JLabel("Name of the evidence file"))
        evidencePanel.add(txtNameEvidence)
        evidencePanel.add(swing.JLabel("Details of the evidence file"))
        evidencePanel.add(txtDescEvidence)
        findingPanel.addAncestorListener(RequestFocusJComponent(txtNameEvidence))

        # Add both parent JPanels (findingPanel,evidencePanel) to the components ArrayList
        components.add(findingPanel)
        components.add(evidencePanel)

        # Show the customized OptionPane and save the result (ok/cancel)
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            components.toArray(),
            "What did you find?",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE,
        )

        # Check if user cancels the action
        if result != swing.JOptionPane.OK_OPTION:
            return False

        # Get the values from the user and create a finding entry
        finding = self.extender.project.findings.get(
            comboboxFindings.getSelectedIndex()
        )
        nameEvidence = txtNameEvidence.getText()
        evidenceDetails = txtDescEvidence.getText()

        if nameEvidence == "":
            Static.showWarning("Warning!", "The evidence name cannot be empty!")
            return False

        self.extender.tableModelEvidences.addEvidenceEntry(
            finding,
            self.messageInfo,
            nameEvidence,
            evidenceDetails,
            evidenceType=Evidence.REQ_RESPONSE_FILE,
            filePathExtraFile="",
        )
        return True


class HandleIncludeSelection(ActionListener):
    """This handler is responsible for replacing everything but the selection with <<SNIP>>
    in the headers/body of a Request/Response"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        """
        Change everything above and below the selectedData to <SNIP>
        IMPORTANT: the msg CANNOT contain \n\n after each other, it will fail
        SOLUTION: put a <space> in between, but then you will receive weird chars in your viewers
        """

        # Get selectedData from requestViewer - selectedData is an array of ascii codes
        # https://python.readthedocs.io/en/v2.7.2/library/array.html
        selectedData = self.extender.requestViewer.getSelectedData()
        isRequest = True

        # If there is nothing selected in the requestViewer, try responseViewer
        if not selectedData:
            selectedData = self.extender.responseViewer.getSelectedData()
            isRequest = False

        # If nothing is selected, exit
        if not selectedData:
            return

        # replace everything except selection with "\n< SNIP >\n"
        msg = [10, 60, 32, 83, 78, 73, 80, 32, 62, 10]
        selectedData.extend(msg)

        msg.reverse()
        selectedData.reverse()

        selectedData.extend(msg)
        selectedData.reverse()

        finding = self.extender.tableModelFindings.getTable().currentFindingEntry
        evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry

        if isRequest:
            self.extender.project.saveHttpReqResp(
                finding,
                evidence,
                selectedData,
                self.extender.responseViewer.getMessage(),
                self.extender,
            )
            self.extender.requestViewer.setMessage(selectedData, isRequest)
        else:
            self.extender.project.saveHttpReqResp(
                finding,
                evidence,
                self.extender.requestViewer.getMessage(),
                selectedData,
                self.extender,
            )
            self.extender.responseViewer.setMessage(selectedData, isRequest)

        self.extender.currentlyDisplayedItem = evidence


class HandleExcludeSelection(ActionListener):
    """This handler is responsible replacing the selection with < SNIP > in a Request/Response"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        # Get selectedData from requestViewer - selectedData is an array of ascii codes
        # https://python.readthedocs.io/en/v2.7.2/library/array.html
        messageData = self.extender.requestViewer.getMessage()
        selectedData = self.extender.requestViewer.getSelectedData()
        isRequest = True

        # If there is nothing selected in the requestViewer, try responseViewer
        if not selectedData:
            messageData = self.extender.responseViewer.getMessage()
            selectedData = self.extender.responseViewer.getSelectedData()
            isRequest = False

        # If nothing is selected, exit
        if not selectedData:
            return

        # Replace the selectedData with "< SNIP >", this will replace all the occurrences
        haystack = self.extender.helpers.bytesToString(messageData)
        needle = self.extender.helpers.bytesToString(selectedData)
        newMessageData = string.replace(haystack, needle, "< SNIP >")

        finding = self.extender.tableModelFindings.getTable().currentFindingEntry
        evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry

        if isRequest:
            self.extender.project.saveHttpReqResp(
                finding,
                evidence,
                self.extender.helpers.stringToBytes(newMessageData),
                self.extender.responseViewer.getMessage(),
                self.extender,
            )
            self.extender.requestViewer.setMessage(newMessageData, isRequest)
        else:
            self.extender.project.saveHttpReqResp(
                finding,
                evidence,
                self.extender.requestViewer.getMessage(),
                self.extender.helpers.stringToBytes(newMessageData),
                self.extender,
            )
            self.extender.responseViewer.setMessage(newMessageData, isRequest)

        self.extender.currentlyDisplayedItem = evidence


class HandleSaveButton(ActionListener):
    """This creates a directory for every finding and creates the corresponding evidence files in .txt file format.
    It also creates a serialized file which holds all the findings and evidences in the parent directory (/Evidences)
    """

    def __init__(self, extender, selectedPath, prefix):
        self.extender = extender
        self.selectedPath = selectedPath
        self.prefix = prefix

    def actionPerformed(self, e):
        location = self.selectedPath.getText()
        prefix = Static.slugify(self.prefix.getText().strip()).upper()

        if not self.validateParams(location, prefix):
            return

        folderEvidences = self.verifyLocation(location)
        if not folderEvidences:
            return

        # REMOVE PREVIOUS FINDINGS  - TODO clean this up
        # folderEvidences = File(location)
        # Static.recurseRemove(folderEvidences)

        # Create and write the evidences and Serialize and save the project
        if self.serializeProject(
            folderEvidences.getAbsolutePath(), prefix
        ) and self.createEvidenceFiles(prefix, folderEvidences.getAbsolutePath()):
            # If everything is saved, show success message and disable AutoSave
            swing.JOptionPane.showMessageDialog(
                Static.getBurpFrame(),
                "Successfully saved!",
                "Saved",
                swing.JOptionPane.PLAIN_MESSAGE,
            )

            self.extender.autoSaveOption.setSelected(False)

            return

        Static.showWarning("Oops!", "Something went wrong :(")

    def serializeProject(self, location, prefix):
        """Serialize the project and write it to evidences.ser"""

        self.extender.project.location = location
        self.extender.project.prefix = prefix

        # REMOVE PREVIOUS FINDINGS  - TODO clean this up
        # folderEvidences = File(location)
        # Static.recurseRemove(folderEvidences)

        # print('BAD SEIRAL CALLED!')
        # autoSave is put to False because we don't want this option to be enabled when someone loads it back
        try:
            self.extender.project.autoSaveProject = False
            serializedProject = File(location + File.separator + "evidences.ser")
            outFile = FileOutputStream(serializedProject)
            outStream = ObjectOutputStream(outFile)
            outStream.writeObject(self.extender.project)
            outFile.close()
            return True
        except IOException as e:
            Static.showError(
                "Warning!",
                "An error occurred when SERIALIZING the project: "
                "\nSee output/error tabs for more info",
            )
            return False

    def createEvidenceFiles(self, code, location):
        """Creates the directories for the findings and writes the Evidence in .txt files"""

        allFindings = self.extender.project.findings

        # Sort the findings in the ArrayList based on severity
        Collections.sort(allFindings, ComparatorSeverityArrayList())

        for i in range(len(allFindings)):
            finding = allFindings.get(i)

            # For every finding make a separate directory based on the uid and the finding.name
            uid = code + str(i + 1).zfill(2)  # A01, A02, ...
            dirFinding = os.path.join(location, uid + " - " + finding.name)

            File(dirFinding).mkdirs()

            # CREATE INFO.TXT (dirty fix) - TODO clean this up
            writer = FileWriter(os.path.join(dirFinding, "info") + ".txt")
            writer.write(finding.getNotes())
            writer.close()

            for j in range(len(finding.evidences)):
                evidence = finding.evidences.get(j)
                fileName = dirFinding + File.separator + evidence.name

                # Determine if evidence is notes or Request/Response and write to a text file
                writer = None
                try:
                    if evidence.evidenceType == Evidence.NON_EDITABLE_FILE:
                        # DIRTY FIX TO FILTER OUT THE INFO-TXT FILES AS THEY ARE CLASSIFIED AS NON EDITABLE
                        if evidence.name != "info":
                            extension = os.path.splitext(
                                str(evidence.filePathExtraFile["filePathExtraFile"])
                            )[1]
                            fileName = fileName + extension
                            shutil.copyfile(
                                evidence.filePathExtraFile["filePathExtraFile"],
                                fileName,
                            )
                            # writer = FileWriter(fileName + ".txt")
                            # writer.write(evidence.content)
                            # writer.close()

                    if evidence.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                        writer = FileWriter(fileName + ".txt")
                        writer.write(evidence.content)
                        writer.close()

                    if evidence.evidenceType == Evidence.REQ_RESPONSE_FILE:
                        request = evidence.getRequestAsString()
                        response = evidence.getResponseAsString()

                        # Check if any rules exist to snip certain headers
                        if len(self.extender.project.rules) > 0:
                            for rule in self.extender.project.rules:
                                if rule.enabled:
                                    request, response = self.snipHeaders(
                                        rule, request, response
                                    )

                        template = self.extender.project.httpReqRespTemplate

                        if "%REQUEST%" in template:
                            result = string.replace(template, "%REQUEST%", request)
                            template = result

                        if "%RESPONSE%" in template:
                            result = string.replace(template, "%RESPONSE%", response)
                            template = result

                        # Write the .txt file
                        writer = FileWriter(fileName + ".txt")
                        writer.write(template)
                        writer.close()

                except IOException as e:
                    Static.showError(
                        "Warning!",
                        "An error occurred when WRITING to: "
                        + fileName
                        + "\nSee OUTPUT for more info",
                    )
                    print(e)

                    if writer:
                        writer.close()
                    return False
        return True

    def validateParams(self, location, prefix):
        # Check if a valid path is given to save/export the findings
        if location == "":
            Static.showWarning("Empty Path!", "Please select a path")
            return False

        # Ask for a prefix
        if prefix == "":
            result = swing.JOptionPane.showInputDialog(
                Static.getBurpFrame(), "What should be the Findings prefix?"
            )

            if not result:
                # User cancelled the action
                return False

            prefix = result.strip()
            self.prefix.setText(prefix)

        # If there are no findings to save, exit
        if len(self.extender.project.findings) < 1:
            Static.showWarning("No Findings!", "There are no Findings to save")
            return False

        return True

    def verifyLocation(self, location):
        # Check Read/Write permissions for the location
        path = File(location)

        if not Files.isWritable(path.toPath()) and path.exists():
            Static.showWarning("Warning!", "Cannot write at the specified location")
            return None

        # Directory Evidences is the parent folder for the export
        path = File(os.path.join(location, "Evidences"))

        # Check if the directory Evidences already exists at the specified location
        if path.exists() and path.isDirectory():
            result = swing.JOptionPane.showConfirmDialog(
                Static.getBurpFrame(),
                "Evidences have been found at this location, if you proceed "
                "all the existing evidences at the location will be "
                "removed/overwritten."
                "\nAre you sure you want to continue?",
                "Attention!",
                swing.JOptionPane.YES_NO_CANCEL_OPTION,
                swing.JOptionPane.WARNING_MESSAGE,
            )
            if result != 0:
                # no/cancel
                return None

            try:
                Static.recurseRemove(path)
                # Give the system time to delete the files otherwise it will error out when combined with autoSaving
                time.sleep(1)
                path.mkdirs()
            except Exception as e:
                Static.showError(
                    "Oops!",
                    "Something unexpected happened when trying to export the evidences"
                    "\nCheck the output and error tabs for more info"
                    "\n\n(It's probably a good idea to restart the plugin)",
                )
                print(e.printStackTrace())
                return None
        else:
            try:
                created = path.mkdirs()
                if not created:
                    Static.showError(
                        "Error creating Evidences dir",
                        "Could not create a Evidences directory at the "
                        "specified location",
                    )
                    return None
            except Exception as e:
                Static.showError(
                    "Oops!",
                    "Something unexpected happened when trying to export the evidences"
                    "\nCheck the output and error tabs for more info"
                    "\n\n(It's probably a good idea to restart the plugin)",
                )
                e.printStackTrace()
                return None

        return path

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


class HandleRecoveryButton(ActionListener):
    """Responsible for trying to recover serialized projects from the temporary folder into the burp plugin"""

    def __init__(self, extender):
        self.extender = extender
        self.project = None

    def actionPerformed(self, e):
        location = tempfile.gettempdir()

        # check if recovery file exists in temporary folder
        if not Files.isReadable(
            File(location + File.separator + "evidences.ser").toPath()
        ):
            Static.showWarning(
                "Warning!",
                "Unfortunately, could not find a recovery file in temporary folder...",
            )
            return

        confirm = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            "A recovery file has been found in the temporary folder. "
            "\nIf you proceed, all findings currently loaded in the plugin will be removed and replaced."
            "\nPlease make sure you save them first if you don't want that to happen!."
            "\nAre you sure you want to continue?",
            "Attention!",
            swing.JOptionPane.YES_NO_CANCEL_OPTION,
            swing.JOptionPane.WARNING_MESSAGE,
        )
        if confirm != 0:
            # no/cancel
            return

        if self.deserializeProject(location):
            # Load the project
            self.extender.project = self.project
            self.extender.project.read_editable_file_content()
            self.extender.tableModelFindings.setFindings(self.extender.project.findings)
            self.extender.tableModelRules.setRules(self.extender.project.rules)
            # avoid empty prefix (projects are not initialized with one for some reason)
            if self.extender.project.prefix == "":
                self.extender.project.prefix = "A"
            self.extender.findingPrefixText.setText(self.extender.project.prefix)

            # Disable autoSaving when a project is loaded
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)

            # If everything is loaded, show success message
            swing.JOptionPane.showMessageDialog(
                Static.getBurpFrame(),
                "Successfully recovered! Please don't forget to immediately save your project!",
                "Recovered",
                swing.JOptionPane.PLAIN_MESSAGE,
            )
            return

        swing.JOptionPane.showMessageDialog(
            Static.getBurpFrame(),
            "Something went wrong :(",
            "Oops",
            swing.JOptionPane.PLAIN_MESSAGE,
        )

    def deserializeProject(self, location):
        try:
            # Deserialize the project
            inFile = FileInputStream(location + File.separator + "evidences.ser")
            inStream = util.PythonObjectInputStream(inFile)
            project = inStream.readObject()
            inStream.close()
            inFile.close()
            # project.print_evidences()
            self.project = project

            return True

        except IOException as e:
            Static.showError(
                "Warning!",
                "An error occurred when deserializing the project."
                "\nMake sure evidences.ser exists at the specified location"
                "\n\nSee output/error tabs for more info",
            )

            inStream.close()
            inFile.close()

            return False


class HandleLoadButton(ActionListener):
    """Responsible for loading existing findings and evidences from a serialized project into the burp plugin"""

    def __init__(self, extender, selectedPath):
        self.extender = extender
        self.selectedPath = selectedPath
        self.project = None

    def actionPerformed(self, e):
        location = self.selectedPath.getText()

        folderEvidences = self.verifyLocation(location)
        if not folderEvidences:
            return

        if self.deserializeProject(folderEvidences.getAbsolutePath()):
            # Load the project
            self.extender.project = self.project
            self.extender.tableModelFindings.setFindings(self.extender.project.findings)
            self.extender.tableModelRules.setRules(self.extender.project.rules)
            self.extender.findingPrefixText.setText(self.extender.project.prefix)

            # Disable autoSaving when a project is loaded
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)

            # If everything is loaded, show success message
            swing.JOptionPane.showMessageDialog(
                Static.getBurpFrame(),
                "Successfully loaded!",
                "Loaded",
                swing.JOptionPane.PLAIN_MESSAGE,
            )
            return

        swing.JOptionPane.showMessageDialog(
            Static.getBurpFrame(),
            "Something went wrong :(",
            "Oops",
            swing.JOptionPane.PLAIN_MESSAGE,
        )

    def deserializeProject(self, location):
        try:
            # Deserialize the project
            inFile = FileInputStream(location + File.separator + "evidences.ser")
            inStream = util.PythonObjectInputStream(inFile)
            project = inStream.readObject()
            inStream.close()
            inFile.close()

            self.project = project
            return True

        except IOException as e:
            Static.showError(
                "Warning!",
                "An error occurred when deserializing the project."
                "\nMake sure evidences.ser exists at the specified location"
                "\n\nSee output/error tabs for more info",
            )
            print(e)
            inStream.close()
            inFile.close()

            return False

    def verifyLocation(self, path):
        # Check if a path is given to save/export the findings
        if path == "":
            Static.showWarning("Empty Path!", "Please select a path")
            return None

        # Chose not to change backslash by forwardslash in location since a location may have a special char in the name
        # e.g. /home/user/Burp\ -\ Findings/....
        # this allows a user to select the Evidences folder itself to load the findings
        if path[-10:] == File.separator + "Evidences":
            self.selectedPath.setText(path[:-10])

        # Check Read permissions for the location
        if not Files.isReadable(File(path + File.separator + "evidences.ser").toPath()):
            Static.showWarning(
                "Warning!", "Cannot read the Evidences at the specified location"
            )
            return None

        # Check if Evidences folder exists
        folderEvidences = File(path)
        if not folderEvidences.exists() or not folderEvidences.isDirectory():
            Static.showWarning(
                "No Evidences",
                "Could not find the Evidences directory at the given path",
            )
            return None

        return folderEvidences


class HandleSelectPath(ActionListener):
    """Responsible for showing a dialog to select a path"""

    def __init__(self, extender, selectedPath):
        self.extender = extender
        self.selectedPath = selectedPath

    def actionPerformed(self, e):
        parentFrame = swing.JFrame()
        fileChooser = swing.JFileChooser()
        fileChooser.setDialogTitle("Specify a directory to save the evidences")
        fileChooser.setFileSelectionMode(swing.JFileChooser.DIRECTORIES_ONLY)

        userSelection = fileChooser.showOpenDialog(parentFrame)

        if userSelection == swing.JFileChooser.APPROVE_OPTION:
            fileLoad = fileChooser.getSelectedFile()
            directoryName = fileLoad.getAbsolutePath()

            self.selectedPath.setText(directoryName)

            # Disable autoSaving when the path has changed
            if self.extender.project:
                self.extender.project.autoSaveProject = False
                self.extender.autoSaveOption.setSelected(False)


class HandleAutoSaveOption(ActionListener):
    """This class is responsible for enabling/disabling the AutoSave feature"""

    def __init__(self, extender, selectedPath, prefix):
        self.extender = extender
        self.selectedPath = selectedPath
        self.prefix = prefix

    def actionPerformed(self, e):
        autoSave = self.extender.autoSaveOption.isSelected()
        success = True  # if any of the methods error out, autoSave can NOT be enabled
        if autoSave:
            location = self.selectedPath.getText()
            prefix = Static.slugify(self.prefix.getText().strip()).upper()

            # Check if a prefix is given to name the exported findings
            if prefix == "":
                Static.showWarning(
                    "Empty prefix!",
                    "Please specify a prefix code which will be used to name the findings",
                )
                self.extender.autoSaveOption.setSelected(False)
                return

            # Check if a path is given to save/export the findings
            if location == "":
                Static.showWarning("Empty Path!", "Please select a path")
                self.extender.autoSaveOption.setSelected(False)
                return

            # Check if the location is writable
            if not Files.isWritable(File(location).toPath()):
                Static.showWarning("Warning!", "Cannot write at the specified location")
                self.extender.autoSaveOption.setSelected(False)
                return

            location = location + File.separator + "Evidences"
            folderEvidences = File(location)

            findingsExist = len(self.extender.project.findings) > 0
            folderEvidencesExist = folderEvidences.exists()

            if not findingsExist and not folderEvidencesExist:
                # silently create the Evidences dir at the location and enable autoSave
                success = self.createEvidencesFolder(folderEvidences)

            elif not findingsExist and folderEvidencesExist:
                # ask the user if he/she wants to delete existing findings at the location? Folder may be empty or not
                success = self.promptUserToContinue(folderEvidences)

            elif findingsExist and not folderEvidencesExist:
                # silently save the findings at the location and enable autoSave
                try:
                    self.extender.saveButton.doClick()
                    success = True
                except Exception:
                    Static.showError(
                        "Oops!",
                        "Something went wrong when trying to save your evidences at the location."
                        "Please check the ERROR tab for more info",
                    )
                    success = False

            else:
                # findingsExist and findingsFolderExist:
                # Deserialize the project and compare with equals and hash
                # compare the findings currently open with the existing findings at the location
                success = self.compareExistingFindingsWithCurrent(folderEvidences)

            if success:
                self.extender.project.location = location
                self.extender.project.prefix = prefix

        if success:
            self.extender.project.autoSaveProject = autoSave
            self.extender.autoSaveOption.setSelected(autoSave)

    def createEvidencesFolder(self, folderEvidences):
        try:
            created = folderEvidences.mkdirs()

            if not created:
                Static.showError(
                    "Error creating Findings dir",
                    "It seems you don't have enough rights to export at the specified location.",
                )
                return False

            return True

        except Exception as e:
            Static.showError(
                "Oops!",
                "Something unexpected happened while trying to create the "
                "Findings directory. Check the output and error tabs of the"
                "plugin for more info.",
            )
            print(e.printStackTrace())
            return False

    def promptUserToContinue(self, folderEvidences):
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            "Evidences have been found at this location, if you proceed all"
            " the existing evidences at the location will be "
            "removed/overwritten."
            "\nAre you sure you want to continue?",
            "Attention!",
            swing.JOptionPane.YES_NO_CANCEL_OPTION,
            swing.JOptionPane.WARNING_MESSAGE,
        )

        # If user cancels the action
        if result != swing.JOptionPane.OK_OPTION:
            self.extender.autoSaveOption.setSelected(False)
            return False

        try:
            # If user agrees, delete the folder and recreate it.
            Static.recurseRemove(folderEvidences)

            # Give the system time to delete the files otherwise it will error out
            time.sleep(1)
            created = folderEvidences.mkdirs()

            if not created:
                Static.showError(
                    "Error creating Evidences dir",
                    "It seems you don't have enough rights "
                    "to export at the specified location.",
                )
                return False

            return True

        except Exception as e:
            Static.showError(
                "Oops!",
                "Something unexpected happened while trying to create the "
                "Evidences directory. Check the output and error tabs of the"
                "plugin for more info.",
            )
            print(e.printStackTrace())
            return False

    def compareExistingFindingsWithCurrent(self, folderEvidences):
        """If the findings at the location equal the findings currently open then silently enable autoSave
        else ask the user if he/she wants to continue as that will delete/overwrite the ones at the location
        """

        try:
            if not File(
                folderEvidences.toString() + File.separator + "evidences.ser"
            ).exists():
                Static.showWarning(
                    "Warning!",
                    "Could not find the evidences.ser file at the location.\n"
                    "Please export your current findings manually and try again.",
                )

                self.extender.autoSaveOption.setSelected(False)  # AutoSave is False
                return False

            # Deserialize the project
            inFile = FileInputStream(
                folderEvidences.toString() + File.separator + "evidences.ser"
            )
            inStream = util.PythonObjectInputStream(inFile)
            project = inStream.readObject()
            inStream.close()
            inFile.close()

            # If the prefix differs then existing findings need to be recreated and project does not equal
            if (
                Static.slugify(self.prefix.getText().strip()).upper()
                != self.extender.project.prefix
            ):
                enable = False
            else:
                enable = self.extender.project.equals(project)

            if enable:
                # Silently enable autoSave
                return True
            else:
                # Ask the user if he/she wants to continue. If he/she agrees, delete the folder and recreate it.
                result = swing.JOptionPane.showConfirmDialog(
                    Static.getBurpFrame(),
                    "Different findings and evidences have been found at this "
                    "location, if you proceed all the existing data at the "
                    "location will be removed/overwritten."
                    "\nAre you sure you want to continue?",
                    "Attention!",
                    swing.JOptionPane.YES_NO_CANCEL_OPTION,
                    swing.JOptionPane.WARNING_MESSAGE,
                )

                # Unset project variable, otherwise can't delete evidences.ser
                project = None

                # If user cancels the action
                if result != swing.JOptionPane.OK_OPTION:
                    self.extender.autoSaveOption.setSelected(False)
                    return False

                Static.recurseRemove(folderEvidences)
                self.extender.saveButton.doClick()
                return True

        except Exception as e:
            Static.showError(
                "Oops!",
                "An error occurred when trying to compare if the current evidences equal "
                "the evidences at the location."
                "\nSee OUTPUT/ERROR tabs of the plugin for more details.",
            )
            print(e)
            inStream.close()
            inFile.close()
            return False


class HandleDeleteFinding(ActionListener):
    """Responsible for deleting a finding"""

    def __init__(self, table, rowIndex):
        self.table = table
        self.extender = table.tableModel.extender
        self.rowIndex = rowIndex
        self.modelRow = self.table.convertRowIndexToModel(rowIndex)

    def actionPerformed(self, e):
        # When a entry is deleted try to select the previous entry in the list, else try to select the next entry.
        # If no prevEntry or nextEntry exists then clean everything
        prevRowIndex = self.rowIndex - 1
        nextRowIndex = self.rowIndex + 1
        reset = False

        # Don't save the FindingEntry that will be deleted
        self.table.currentFindingEntry = -1
        self.extender.tableModelEvidences.getTable().currentEvidenceEntry = -1

        # Select a new findingEntry (if it exists) before deleting else reset(clean) the layout
        if prevRowIndex > -1:
            self.table.changeSelection(prevRowIndex, 1, False, False)
        elif nextRowIndex < len(self.table.tableModel.findings):
            self.table.changeSelection(nextRowIndex, 1, False, False)
        else:
            reset = True

        # Remove the entry and redraw the table findings
        self.table.tableModel.removeFindingEntry(self.modelRow)
        self.table.tableModel.fireTableRowsDeleted(self.rowIndex, self.rowIndex)

        # Clean everything
        if reset:
            self.extender.reset()


class HandleDeleteEvidence(ActionListener):
    """Responsible for deleting an evidence file"""

    def __init__(self, table, rowIndex):
        self.table = table
        self.extender = table.tableModel.extender
        self.rowIndex = rowIndex
        self.modelRow = self.table.convertRowIndexToModel(rowIndex)

    def actionPerformed(self, e):
        # When a entry is deleted try to select the previous entry in the list, else try to select the next entry.
        # If no prevEntry or nextEntry exists then clean everything, info.txt does not count as an entry
        prevRowIndex = self.rowIndex - 1
        nextRowIndex = self.rowIndex + 1
        reset = False

        # Don't save the EvidenceEntry that will be deleted
        self.table.currentEvidenceEntry = -1

        # Select a new EvidenceEntry (if it exists) before deleting else reset
        if prevRowIndex > 0:
            self.table.changeSelection(prevRowIndex, 1, False, False)
        elif nextRowIndex < len(self.table.tableModel.evidences):
            self.table.changeSelection(nextRowIndex, 1, False, False)
        else:
            reset = True

        # Get the selected row of the findingsTable
        findingRowIndex = self.extender.tableModelFindings.getTable().getSelectedRow()
        findingModelRow = (
            self.extender.tableModelFindings.getTable().convertRowIndexToModel(
                findingRowIndex
            )
        )

        table_model = self.table.tableModel

        # Remove the entry and redraw the table findings
        self.table.tableModel.removeEvidenceEntry(findingModelRow, self.modelRow)

        i = 0

        for evidence in table_model.getEvidences():
            if re.match(r"^evidence[0-9][0-9]$", evidence.name):
                i += 1

                evidence.setName("evidence" + str(i).zfill(2))

        self.table.tableModel.fireTableRowsDeleted(self.rowIndex, self.rowIndex)

        # If no evidence entries exist anymore, return empty table  ###
        if reset:
            self.nextEvidenceEntry = None
            self.extender.tabReqResp.setSelectedIndex(2)
            self.extender.tabReqResp.setEnabledAt(1, False)
            self.extender.tabReqResp.setEnabledAt(2, False)
            self.extender.tabReqResp.setEnabledAt(0, False)
            self.extender.snipButtonPanel.setVisible(False)
            self.extender.btnRevertMessage.setVisible(False)
            self.extender.responseViewer.setMessage([], False)
            self.extender.requestViewer.setMessage([], False)
            self.extender.editableFileTextViewer.setText([])
            self.extender.editableFileTextViewer.setEditable(False)

        # findingTable = self.extender.tableModelFindings.getTable()
        # findingRowIndex = findingTable.getSelectedRow()

        #    delete = swing.JButton("")
        #    delete.addActionListener(
        #        HandleDeleteFinding(findingTable, findingRowIndex))
        #    delete.doClick()


class HandleChangeFindingCombobox(ActionListener):
    """This class is responsible for changing the evidence sequence nr when adding an evidence to an existing finding"""

    def __init__(self, extender, combobox, evidenceTextBox):
        self.extender = extender
        self.combo = combobox
        self.evidenceText = evidenceTextBox

    def actionPerformed(self, e):
        finding = self.extender.project.findings.get(self.combo.getSelectedIndex())

        index = self.extender.project.findings.indexOf(finding)
        count = len(self.extender.project.findings.get(index).evidences)
        self.evidenceText.setText(
            self.extender.project.evidenceFileName + str(count).zfill(2)
        )


class HandleAddRule(ActionListener):
    """Add a rule which specifies which header values should be redacted"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        # Standard headers
        headers = [
            "Host",
            "User-Agent",
            "Set-Cookie",
            "Cookie",
            "Referer",
            "Content-Length",
            "Transfer-Encoding",
            "Server",
            "Accept",
            "Connection",
            "Content-Encoding",
            "Content-Type",
            "Date",
            "Location",
            "Vary",
            "Last-Modified",
        ]

        # ArrayList components holds all our JComponent objects
        components = ArrayList()
        parentPane = swing.JPanel(BorderLayout())
        parentPane.setPreferredSize(Dimension(400, 200))

        # Create topPanel - it holds the combobox with the headers
        comboboxHeaders = swing.JComboBox(headers)
        topPanel = swing.JPanel(GridLayout(2, 1))
        topPanel.add(swing.JLabel("Specify a header whose values should be filtered"))
        topPanel.add(comboboxHeaders)

        # Create bottomPanel - it holds a textbox for non standard headers
        lblNameHeader = swing.JLabel("Non-Standard header: ")
        lblNameHeader.setPreferredSize(Dimension(140, 30))
        txtNameHeader = swing.JTextField()
        txtNameHeader.setPreferredSize(Dimension(250, 30))

        bottomPanel = swing.JPanel()
        bottomPanel.add(lblNameHeader)
        bottomPanel.add(txtNameHeader)

        # Add both parent JPanels (findingPanel,evidencePanel) to the components ArrayList
        parentPane.add(topPanel, BorderLayout.PAGE_START)
        parentPane.add(bottomPanel, BorderLayout.LINE_START)
        components.add(parentPane)

        # Show the customized OptionPane and save the result (ok/cancel)
        result = swing.JOptionPane.showConfirmDialog(
            Static.getBurpFrame(),
            components.toArray(),
            "Add a header",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE,
        )

        # Check if user cancels the action
        if result != swing.JOptionPane.OK_OPTION:
            return

        if txtNameHeader.getText() == "":
            value = comboboxHeaders.getSelectedItem()
        else:
            value = txtNameHeader.getText()

        for c in value:
            if c not in utils.whitelist:
                Static.showWarning(
                    "Warning!", "A character not part of the whitelist was entered"
                )
                return

        self.extender.tableModelRules.addRuleEntry(value)


class HandleDeleteRule(ActionListener):
    """Deletes a rule in the tableRules"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        selectedIndex = self.extender.tableModelRules.getTable().getSelectedRow()

        if selectedIndex == -1:
            return

        self.extender.tableModelRules.deleteRuleEntry(selectedIndex)


class HandleRevertMessage(ActionListener):
    """Responsible for reverting a response or request depending on the currently open message"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        # Revert a modified Request or Response to its original state (the state when it was sent to the plugin)
        finding = self.extender.tableModelFindings.getTable().currentFindingEntry
        evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry
        if finding == -1 or evidence == -1:
            return

        selectedPane = self.extender.tabReqResp.getSelectedIndex()
        if selectedPane == 0:
            originalRequest = evidence.backUpHttpReqResp.getRequest()
            self.extender.requestViewer.setMessage(originalRequest, True)

        elif selectedPane == 1:
            originalResponse = evidence.backUpHttpReqResp.getResponse()
            self.extender.responseViewer.setMessage(originalResponse, False)

        self.extender.project.saveHttpReqResp(
            finding,
            evidence,
            evidence.backUpHttpReqResp.getRequest(),
            evidence.backUpHttpReqResp.getResponse(),
            self.extender,
        )
        self.extender.currentlyDisplayedItem = evidence.backUpHttpReqResp
        return


class HandleTemplateNotesChangeType(ActionListener):
    """Responsible for changing what is added to the notes"""

    def __init__(self, extender, label, previousIndex):
        self.extender = extender
        self.label = label
        self.previousIndex = previousIndex

    def actionPerformed(self, e):
        # If Finding is selected in comboboxNotesType
        if (
            self.extender.comboboxNotesType.getSelectedIndex() == 0
            and self.previousIndex != 0
        ):
            self.previousIndex = 0
            text = "What should be added to the notes when a Finding is added?"

            self.extender.notesEvidenceTemplate = (
                self.extender.textAreaNotesTemplate.getText()
            )
            self.extender.textAreaNotesTemplate.setText(
                self.extender.notesFindingTemplate
            )

            # Need to set this to False otherwise HandleConfigurationAddOption will be called
            # because new items are added
            self.extender.comboboxNotesOptionsChangedManually = False

            self.extender.comboboxNotesOptions.removeAllItems()
            self.extender.comboboxNotesOptions.addItem("NAME")
            self.extender.comboboxNotesOptions.addItem("SEVERITY")
            self.extender.comboboxNotesOptionsChangedManually = True

        elif (
            self.extender.comboboxNotesType.getSelectedIndex() == 1
            and self.previousIndex != 1
        ):
            self.previousIndex = 1
            text = "What should be added to the notes when an Evidence is added?"

            self.extender.notesFindingTemplate = (
                self.extender.textAreaNotesTemplate.getText()
            )
            self.extender.textAreaNotesTemplate.setText(
                self.extender.notesEvidenceTemplate
            )

            # Need to set this to False otherwise HandleConfigurationAddOption will be called
            # because new items are added
            self.extender.comboboxNotesOptionsChangedManually = False

            self.extender.comboboxNotesOptions.removeAllItems()
            self.extender.comboboxNotesOptions.addItem("NAME")
            self.extender.comboboxNotesOptions.addItem("DETAILS")
            self.extender.comboboxNotesOptions.addItem("HOST")
            self.extender.comboboxNotesOptions.addItem("PORT")
            self.extender.comboboxNotesOptions.addItem("PROTOCOL")
            self.extender.comboboxNotesOptionsChangedManually = True
        else:
            return

        self.label.setText(text)


class HandleTemplateNotesAddOption(ActionListener):
    """When the user clicks on an item in the comboboxNotesOptions in the ConfigurationPane the selected option should be
    added to the textArea"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        # Only when an item is selected by the user and not when items are added programmatically
        # --> happens because items in the combobox are deleted and re-added
        if self.extender.comboboxNotesOptionsChangedManually:
            value = self.extender.comboboxNotesOptions.getSelectedItem()
            text = (
                self.extender.helpers.bytesToString(
                    self.extender.textAreaNotesTemplate.getText()
                )
                + "%"
                + value
                + "%"
            )
            self.extender.textAreaNotesTemplate.setText(text)


class HandleSaveNotesTemplate(ActionListener):
    """User clicked on Save for the notes template"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        if self.extender.comboboxNotesType.getSelectedIndex() == 1:
            self.extender.project.notesFindingTemplate = (
                self.extender.helpers.bytesToString(self.extender.notesFindingTemplate)
            )
            self.extender.project.notesEvidenceTemplate = (
                self.extender.helpers.bytesToString(
                    self.extender.textAreaNotesTemplate.getText()
                )
            )

        if self.extender.comboboxNotesType.getSelectedIndex() == 0:
            self.extender.project.notesFindingTemplate = (
                self.extender.helpers.bytesToString(
                    self.extender.textAreaNotesTemplate.getText()
                )
            )
            self.extender.project.notesEvidenceTemplate = (
                self.extender.helpers.bytesToString(self.extender.notesEvidenceTemplate)
            )

        swing.JOptionPane.showMessageDialog(
            Static.getBurpFrame(),
            "Saved the notes template!",
            "Saved",
            swing.JOptionPane.PLAIN_MESSAGE,
        )


class HandleClearNotesTemplate(ActionListener):
    """User clicked on Clear for the notes template"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        self.extender.textAreaNotesTemplate.setText("")
        self.extender.notesFindingTemplate = ""
        self.extender.notesEvidenceTemplate = ""


class HandleTemplateHttpReqRespAddOption(ActionListener):
    """When the user click on an item in the comboboxTemplateHttpReqRespOptions the selected option should be
    added to the textArea"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        value = self.extender.comboboxTemplateHttpReqRespOptions.getSelectedItem()
        text = (
            self.extender.helpers.bytesToString(
                self.extender.textAreaHttpReqRespTemplate.getText()
            )
            + "%"
            + value
            + "%"
        )
        self.extender.textAreaHttpReqRespTemplate.setText(text)


class HandleSaveHttpReqRespTemplate(ActionListener):
    """User clicked on Save for the evidence template"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        self.extender.project.httpReqRespTemplate = self.extender.helpers.bytesToString(
            self.extender.textAreaHttpReqRespTemplate.getText()
        )

        swing.JOptionPane.showMessageDialog(
            Static.getBurpFrame(),
            "Saved the Request/Response template!",
            "Saved",
            swing.JOptionPane.PLAIN_MESSAGE,
        )


class HandleClearHttpReqRespTemplate(ActionListener):
    """User clicked on Clear for the evidence template"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        self.extender.textAreaHttpReqRespTemplate.setText("")
        self.extender.httpReqRespTemplate = ""


class HandleSaveExportFileNames(ActionListener):
    """Responsible for changing how the notes and evidence files are named"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        notesFileName = self.extender.textBoxNotesName.getText()
        evidenceFileName = self.extender.textBoxEvidenceName.getText()

        for c in notesFileName:
            if c not in utils.whitelist:
                Static.showWarning(
                    "Warning!", "A character not part of the whitelist was entered"
                )
                return

        for c in evidenceFileName:
            if c not in utils.whitelist:
                Static.showWarning(
                    "Warning!", "A character not part of the whitelist was entered"
                )
                return

        self.extender.project.updateNotesFileName(notesFileName)
        self.extender.project.updateEvidencesFileName(evidenceFileName)

        # Disable autoSave when the fileNames are changed
        if self.extender.project.autoSaveProject:
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)

            swing.JOptionPane.showMessageDialog(
                Static.getBurpFrame(),
                "Notes and Evidence naming schema updated!\n\n"
                "Note that AutoSave has been disabled",
                "Saved",
                swing.JOptionPane.PLAIN_MESSAGE,
            )
            return

        swing.JOptionPane.showMessageDialog(
            Static.getBurpFrame(),
            "Notes and Evidence naming schema updated!",
            "Saved",
            swing.JOptionPane.PLAIN_MESSAGE,
        )
