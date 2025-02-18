from javax import swing
from javax.swing.event import AncestorListener, DocumentListener
from java.awt.event import ActionListener, ComponentListener
from java.awt import Color
from java.lang import Runnable
from modules.evidence import Evidence


class RequestHighlightTab(ActionListener):
    """This class is responsible for highlighting the tab whenever a finding/evidence is added"""

    def __init__(self, extender):
        self.extender = extender

    def actionPerformed(self, e):
        """Reset the highlight to BLACK after 3 seconds"""
        tabbedPane = self.extender.getUiComponent().getParent()
        collectorPane = self.extender.getUiComponent()

        if tabbedPane:
            for i in range(tabbedPane.getTabCount()):
                if tabbedPane.getComponentAt(i) == collectorPane:
                    tabbedPane.setBackgroundAt(i, Color.BLACK)
                    break


class RequestFocusJComponent(AncestorListener):
    """Set the focus on the element - used to focus the JTextField when creating or adding a new finding
    Better way but not really possible in Jython
    https://stackoverflow.com/questions/6251665/setting-component-focus-in-joptionpane-showoptiondialog/21426340#21426340
    """

    def __init__(self, element):
        self.element = element

    def ancestorAdded(self, e):
        # this doesn't work for linux systems..
        # self.element.requestFocusInWindow()

        swing.SwingUtilities.invokeLater(RequestFocusHelper(self, self.element))

    def ancestorMoved(self, e):
        pass

    def ancestorRemoved(self, e):
        pass


class RequestFocusHelper(Runnable):
    """https://stackoverflow.com/questions/6251665/setting-component-focus-in-joptionpane-showoptiondialog"""

    def __init__(self, al, element):
        self.ancestorListener = al
        self.element = element

    def run(self):
        self.element.requestFocusInWindow()
        self.element.removeAncestorListener(self.ancestorListener)


class TextBoxListener(DocumentListener):
    """When the path to save the findings is changed autoSave will be set OFF"""

    def __init__(self, extender):
        self.extender = extender

    def changedUpdate(self, e):
        if self.extender.project:
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)

    def insertUpdate(self, e):
        if self.extender.project:
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)

    def removeUpdate(self, e):
        if self.extender.project:
            self.extender.project.autoSaveProject = False
            self.extender.autoSaveOption.setSelected(False)


class PluginLosesFocus(ComponentListener):
    """This class is responsible for saving notes and req/resp when the plugin tab loses focus"""

    def __init__(self, extender):
        self.extender = extender

    def componentHidden(self, e):
        # If the tab overview was selected and another tab in Burp Suite is selected --> Save the changes
        finding = self.extender.tableModelFindings.getTable().currentFindingEntry
        if self.extender.parentPane.getSelectedIndex() == 0 and finding != -1:
            evidence = self.extender.tableModelEvidences.getTable().currentEvidenceEntry
            notes = self.extender.helpers.bytesToString(self.extender.textArea.getText())
            request = self.extender.requestViewer.getMessage()
            response = self.extender.responseViewer.getMessage()
            txtfile = self.extender.editableFileTextViewer.getText()

            self.extender.project.saveNotes(finding, notes)
            if evidence != None:
                if evidence.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                    self.extender.project.saveEditableTextFile(finding, evidence, txtfile)
                if evidence.evidenceType == Evidence.REQ_RESPONSE_FILE:
                    self.extender.project.saveHttpReqResp(finding, evidence, request, response, self.extender)
                if evidence.evidenceType == Evidence.NON_EDITABLE_FILE and evidence.isTextBased():
                    self.extender.project.saveEditableTextFile(finding, evidence, txtfile)

    def componentShown(self, e):
        pass

    def componentMoved(self, e):
        pass

    def componentResized(self, e):
        pass
