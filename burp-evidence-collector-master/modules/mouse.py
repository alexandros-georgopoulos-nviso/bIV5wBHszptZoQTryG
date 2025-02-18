from java.awt.event import MouseAdapter
from javax import swing
from evidence import Evidence

from handlers import HandleDeleteFinding, HandleDeleteEvidence
import tables


class ChangeTab(MouseAdapter):
    """This class is responsible for saving the findings when the tab is changed from General to Import/Export"""

    def __init__(self, extender, target):
        self.extender = extender
        self.target = target

    def mouseReleased(self, evt):
        # If the selected Component does not equal the target Component then save the finding
        # e.g. If the tab General is NOT selected save the findings
        selectedTab = evt.getComponent().getSelectedIndex()

        self.setBurpProjectName()
        if self.target != evt.getComponent().getComponent(selectedTab):
            finding = self.extender.tableModelFindings.getTable().currentFindingEntry

            if finding != -1:
                evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry
                notes = self.extender.helpers.bytesToString(self.extender.textArea.getText())
                request = self.extender.requestViewer.getMessage()
                response = self.extender.responseViewer.getMessage()
                txtfile = self.extender.editableFileTextViewer.getText()

                self.extender.project.saveNotes(finding, notes)
                if evidence.evidenceType == Evidence.REQ_RESPONSE_FILE:
                    self.extender.project.saveHttpReqResp(finding, evidence, request, response, self.extender)
                self.extender.project.saveHttpReqResp(finding, evidence, request, response, self.extender)
                if evidence.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                    self.extender.project.saveEditableTextFile(finding, evidence, txtfile)
                if evidence.evidenceType == Evidence.NON_EDITABLE_FILE and evidence.isTextBased():
                    self.extender.project.saveEditableTextFile(finding, evidence, txtfile)

    def setBurpProjectName(self):
        """Tries to get the project name of Burp - With professional license this contains the path where the findings
        should be saved
        https://stackoverflow.com/questions/57818869/java-awt-get-title-of-root-window"""

        if len(self.extender.selectPathText.getText()) == 0:
            window = swing.SwingUtilities.windowForComponent(self.extender.parentPane)
            title = window.getTitle()
            path = title[title.index(" - ") + 3 :]

            self.extender.selectPathText.setText(path)


class MouseClick(MouseAdapter):
    """When the user clicks the leftMouseButton inside the notes textArea or in the Response/Request viewers
    data will be saved. This is used so autoSaveProject will work better"""

    def __init__(self, extender):
        self.extender = extender

    def mouseReleased(self, evt):
        finding = self.extender.tableModelFindings.getTable().currentFindingEntry
        evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry
        notes = self.extender.helpers.bytesToString(self.extender.textArea.getText())
        request = self.extender.requestViewer.getMessage()
        response = self.extender.responseViewer.getMessage()

        self.extender.project.saveNotes(finding, notes)
        self.extender.project.saveHttpReqResp(finding, evidence, request, response, self.extender)


class RightMouseClick(MouseAdapter):
    """When the user clicks the rightMouseButton inside the tableFindings or tableEvidences
    a menu is shown with the option delete
    """

    def __init__(self, table):
        self.table = table
        self.extender = table.tableModel.extender

    def mouseReleased(self, evt):
        """Create a Popup menu with the options Delete"""
        if swing.SwingUtilities.isRightMouseButton(evt) and isinstance(self.table, tables.TableFindings):
            # Save the evidence files of the finding before changing selection
            self.table.saveEvidences()

            row = self.table.rowAtPoint(evt.getPoint())
            if 0 <= row < self.table.getRowCount():
                self.table.setRowSelectionInterval(row, row)
            else:
                self.table.clearSelection()

            rowIndex = self.table.getSelectedRow()
            self.table.setRowSelectionInterval(rowIndex, rowIndex)
            if rowIndex < 0:
                return

            popup = swing.JPopupMenu()

            # Add Delete menuItem
            deleteMenuItem = swing.JMenuItem("Delete")
            deleteMenuItem.addActionListener(HandleDeleteFinding(self.table, rowIndex))
            popup.add(deleteMenuItem)

            # Show the popup
            popup.show(evt.getComponent(), evt.getX(), evt.getY())

        if swing.SwingUtilities.isRightMouseButton(evt) and isinstance(self.table, tables.TableEvidences):
            # Save the evidence file before changing selection
            self.table.saveEvidence()

            row = self.table.rowAtPoint(evt.getPoint())
            if 0 <= row < self.table.getRowCount():
                self.table.setRowSelectionInterval(row, row)
            else:
                self.table.clearSelection()

            rowIndex = self.table.getSelectedRow()
            self.table.setRowSelectionInterval(rowIndex, rowIndex)
            if rowIndex < 0:
                return

            popup = swing.JPopupMenu()

            # Add Delete menuItem
            deleteMenuItem = swing.JMenuItem("Delete")
            deleteMenuItem.addActionListener(HandleDeleteEvidence(self.table, rowIndex))
            popup.add(deleteMenuItem)

            # Show the popup
            popup.show(evt.getComponent(), evt.getX(), evt.getY())


class ClickConfigurationTab(MouseAdapter):
    """When the configuration tab is clicked the templates should be updated"""

    def __init__(self, extender, tabConfiguration):
        self.extender = extender
        self.tabConfiguration = tabConfiguration

    def mouseReleased(self, evt):
        selectedTab = evt.getComponent().getSelectedIndex()

        # If the selectedSubTab is Templates
        if self.tabConfiguration == evt.getComponent().getComponent(selectedTab):
            self.extender.comboboxNotesType.setSelectedIndex(0)
            self.extender.notesFindingTemplate = self.extender.project.notesFindingTemplate
            self.extender.notesEvidenceTemplate = self.extender.project.notesEvidenceTemplate
            self.extender.textAreaNotesTemplate.setText(self.extender.notesFindingTemplate)

            self.extender.comboboxTemplateHttpReqRespOptions.setSelectedIndex(0)
            self.extender.httpReqRespTemplate = self.extender.project.httpReqRespTemplate
            self.extender.textAreaHttpReqRespTemplate.setText(self.extender.httpReqRespTemplate)

            self.extender.textBoxNotesName.setText(self.extender.project.notesFileName)
            self.extender.textBoxEvidenceName.setText(self.extender.project.evidenceFileName)
