from modules import evidence, finding
from javax import swing
from javax.swing.table import TableRowSorter
from mouse import RightMouseClick
from evidence import Evidence
import utils


class TableFindings(swing.JTable):
    """A custom JTable which shows all the findings"""

    currentFindingEntry = -1
    nextFindingEntry = -1

    def __init__(self, tableModel):
        self.extender = tableModel.extender
        self.tableModel = tableModel
        self.setModel(tableModel)
        self.addMouseListener(RightMouseClick(self))
        self.setRowSelectionAllowed(True)
        self.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)

    def changeSelection(self, row, col, toggle, extend):
        # Save the selected evidences of the current selected finding before changing to the next
        if self.currentFindingEntry != -1:
            self.saveEvidences()

        # Get the next selected findingEntry from the findings table and update the evidence table
        modelRow = self.convertRowIndexToModel(row)
        self.nextFindingEntry = self.tableModel.findings.get(modelRow)
        self.extender.tableModelEvidences.setEvidences(self.nextFindingEntry.evidences)

        # Load the notes of the newly selected finding
        notes = self.nextFindingEntry.evidences.get(0).notes
        self.extender.textArea.setText(notes)

        # Make the selection change
        swing.JTable.changeSelection(self, row, col, toggle, extend)

        # Select the first ReqResp when a different finding is selected

        self.extender.tableModelEvidences.getTable().changeSelection(1, 1, False, False)

        # The nextFindingEntry has been selected
        self.currentFindingEntry = self.nextFindingEntry

    def saveEvidences(self):
        """TableFindings - Save the evidence files of the current finding Entry"""
        # Save info.txt before selecting the new finding entry
        notes = self.extender.helpers.bytesToString(self.extender.textArea.getText())

        # Save the Request/Response before selecting the new finding entry
        modifiedRequest = self.extender.requestViewer.getMessage()
        modifiedResponse = self.extender.responseViewer.getMessage()

        self.extender.project.saveNotes(self.currentFindingEntry, notes)
        currentEvidenceEntry = self.extender.tableModelEvidences.getTable().currentEvidenceEntry
        if currentEvidenceEntry != -1:
            self.extender.project.saveHttpReqResp(
                self.currentFindingEntry, currentEvidenceEntry, modifiedRequest, modifiedResponse, self.extender
            )

    @staticmethod
    def getCurrentSelectedFinding(extender):
        selected_row = extender.tableModelFindings.getTable().getSelectedRow()
        finding_str = extender.tableModelFindings.getValueAt(selected_row, 1)

        for index, i in enumerate(extender.project.findings):
            if i.name == finding_str:
                return (index, i)


class TableEvidences(swing.JTable):
    """A custom JTable which shows all the evidences"""

    currentEvidenceEntry = -1
    nextEvidenceEntry = -1

    def __init__(self, tableModel):
        self.extender = tableModel.extender
        self.tableModel = tableModel
        self.setModel(tableModel)
        self.addMouseListener(RightMouseClick(self))
        self.setRowSelectionAllowed(True)
        self.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)

    def changeSelection(self, row, col, toggle, extend):
        # Save the current (modified) evidence file before selecting the next evidence file

        if self.currentEvidenceEntry != -1:
            self.saveEvidence()

        # If no evidences, display empty table
        if len(self.tableModel.evidences) == 1:
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
        else:
            modelRow = self.convertRowIndexToModel(row)
            self.nextEvidenceEntry = self.tableModel.getEvidences().get(modelRow)

            # Disable selecting the notes file
            if self.extender.project.notesFileName == self.nextEvidenceEntry.name:
                self.nextEvidenceEntry = self.currentEvidenceEntry
                return

            if (
                self.nextEvidenceEntry.evidenceType == Evidence.EDITABLE_TEXT_FILE
                or self.nextEvidenceEntry.evidenceType == Evidence.NON_EDITABLE_FILE
            ):
                self.extender.tabReqResp.setEnabledAt(1, False)
                self.extender.tabReqResp.setEnabledAt(2, True)
                self.extender.tabReqResp.setEnabledAt(0, False)
                self.extender.tabReqResp.setSelectedIndex(2)
                self.extender.snipButtonPanel.setVisible(False)
                self.extender.btnRevertMessage.setVisible(False)
                self.extender.responseViewer.setMessage([], False)
                self.extender.requestViewer.setMessage([], False)
                self.extender.editableFileTextViewer.setEditable(False)
                self.extender.editableFileTextViewer.setText([])
                if self.nextEvidenceEntry.evidenceType == Evidence.NON_EDITABLE_FILE and self.nextEvidenceEntry.isTextBased():
                    self.extender.editableFileTextViewer.setEditable(True)
                    filecontent = utils.read_file(self.nextEvidenceEntry.filePath)
                    self.extender.editableFileTextViewer.setText(filecontent)

                if self.nextEvidenceEntry.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                    self.extender.editableFileTextViewer.setText(self.nextEvidenceEntry.content)
                    self.extender.editableFileTextViewer.setEditable(True)

            if self.nextEvidenceEntry.evidenceType == Evidence.REQ_RESPONSE_FILE:
                self.extender.tabReqResp.setEnabledAt(1, True)
                self.extender.tabReqResp.setEnabledAt(2, False)
                self.extender.tabReqResp.setEnabledAt(0, True)
                self.extender.tabReqResp.setSelectedIndex(0)
                self.extender.snipButtonPanel.setVisible(True)
                self.extender.btnRevertMessage.setVisible(True)
                self.extender.currentlyDisplayedItem = self.nextEvidenceEntry.httpReqResp
                self.extender.requestViewer.setMessage(self.nextEvidenceEntry.httpReqResp.getRequest(), True)
                self.extender.editableFileTextViewer.setEditable(False)

                # A Request may or may not have a Response
                response = self.nextEvidenceEntry.httpReqResp.getResponse()
                if response:
                    self.extender.responseViewer.setMessage(response, False)
                else:
                    self.extender.responseViewer.setMessage([], False)
                self.extender.editableFileTextViewer.setText([])

            # if self.nextEvidenceEntry.evidenceType == Evidence.NON_EDITABLE_FILE:
            #     self.extender.tabReqResp.setSelectedIndex(2)
            #     self.extender.tabReqResp.setEnabledAt(1, False)
            #     self.extender.tabReqResp.setEnabledAt(2, False)
            #     self.extender.tabReqResp.setEnabledAt(0, False)
            #     self.extender.snipButtonPanel.setVisible(False)
            #     self.extender.btnRevertMessage.setVisible(False)
            #     self.extender.responseViewer.setMessage([], False)
            #     self.extender.requestViewer.setMessage([], False)
            #     self.extender.editableFileTextViewer.setText([])
            #     self.extender.editableFileTextViewer.setEditable(False)

        # Make the selection change
        swing.JTable.changeSelection(self, row, col, toggle, extend)

        # The next evidenceEntry has been selected
        self.currentEvidenceEntry = self.nextEvidenceEntry

    def saveEvidence(self):
        """TableEvidences - Save the (modified) evidence file"""
        # FIXME : save the modified evidence / editable evidence text!
        # Save the Request/Response before selecting the new finding entry

        currentEvidence = self.currentEvidenceEntry
        currentFinding = self.extender.tableModelFindings.getTable().currentFindingEntry

        if currentEvidence == None:
            return

        if currentEvidence.evidenceType == Evidence.REQ_RESPONSE_FILE:
            modifiedRequest = self.extender.requestViewer.getMessage()
            modifiedResponse = self.extender.responseViewer.getMessage()
            self.extender.project.saveHttpReqResp(currentFinding, currentEvidence, modifiedRequest, modifiedResponse, self.extender)

        if currentEvidence.evidenceType == Evidence.EDITABLE_TEXT_FILE:
            self.extender.project.saveEditableTextFile(
                currentFinding, currentEvidence, self.extender.editableFileTextViewer.getText()
            )
        if currentEvidence.evidenceType == Evidence.NON_EDITABLE_FILE:
            if currentEvidence.isTextBased():
                self.extender.project.saveEditableTextFile(
                    currentFinding, currentEvidence, self.extender.editableFileTextViewer.getText()
                )


class TableRules(swing.JTable):
    """A custom JTable which holds all the rules"""

    def __init__(self, tableModel):
        self.extender = tableModel.extender
        self.tableModel = tableModel
        self.setModel(tableModel)
        self.setRowSelectionAllowed(True)
        self.setSelectionMode(swing.ListSelectionModel.SINGLE_SELECTION)

    def changeSelection(self, row, col, toggle, extend):
        # Make the selection change
        swing.JTable.changeSelection(self, row, col, toggle, extend)

        return
