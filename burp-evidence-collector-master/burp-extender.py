from burp import IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, ITextEditor, IExtensionStateListener
from javax import swing
from java.awt import BorderLayout, GridLayout, Dimension, Color, Font
from java.util import ArrayList

from modules.project import Project
from modules.serializable import HttpRequestResponse, HttpService
from modules.table_models import TableModelFindings, TableModelEvidences, TableModelRules
from modules.mouse import ChangeTab, MouseClick, ClickConfigurationTab
from modules.misc import TextBoxListener, PluginLosesFocus
import modules.handlers as handlers

import sys

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, ITextEditor, IExtensionStateListener):
    """To anyone who reads this;
    1. When you see extender in other classes it is a reference to this class. This is the spine of the plug-in.
    2. There are some optimizations possible in the code...
    3. When you see the messageInfo variable it is an httpRequestResponse object
    4. Known quirks:
        4.1 plug-in will stop working correctly when AutoSave is actively used and the Evidences directory is removed
        --> FIX: disable AutoSave and manually export your findings
        4.2 when two or more identical findings are added AutoSave will only save correct copies of the first one.
            findings are identical when they have the same name, severity, evidence files, notes
        --> FIX: don't do it ;)
        ( I could put a constraint but it will slightly impact performance as I have to compare all the existing ones )
    """

    def registerExtenderCallbacks(self, callbacks):
        # Required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        # sys.stdout = callbacks.getStdout()

        self.project = Project()
        self.currentlyDisplayedItem = None

        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # set our extension name
        self.callbacks.setExtensionName("Evidence Collector")

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # Create the parent pane for overview, config, extra
        self.parentPane = swing.JTabbedPane()

        # Create the tab overview, here you can select/edit findings and evidences (Request/Response) and take notes
        self.createTabOverview()
        self.parentPane.addTab("Overview", self.tabOverview)

        # Create the tab import/export, here you can export your findings and/or import existing findings.
        self.createTabImportExport()
        self.parentPane.addTab("Import/Export", self.tabIExport)

        self.createTabConfiguration()
        self.parentPane.addTab("Configuration", self.tabConfiguration)

        # Add listener which will save the findings when the tabs are changed away from "Overview"
        # works only for the tabs in the burp plugin
        self.parentPane.addMouseListener(ChangeTab(self, self.tabOverview))
        self.parentPane.addMouseListener(ClickConfigurationTab(self, self.tabConfiguration))

        # customize our UI components
        self.callbacks.customizeUiComponent(self.parentPane)

        # register for custom context menu items
        self.callbacks.registerContextMenuFactory(self)

        self.parentPane.addComponentListener(PluginLosesFocus(self))
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        print 'The Evidence Collector plugin has been initialized successfully...'
        print ''
        print 'If you find any bugs or have some additional features in mind, please let us know on the GitHub page!'
        print ''
        return

    def createTabOverview(self):
        """The tab which gives an overview of the current findings and evidences"""

        # create the tab overview
        self.tabOverview = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.tabOverview.setDividerLocation(400)

        # Create leftPane, this is split in top and bottom.
        # Top has a table with all the findings. Bottom has a table with all the evidence files of that finding.
        self.leftPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        # Create rightPane, holds the notes in the upper right and the request/response in the lower right
        self.rightPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self.rightPane.setDividerLocation(250)

        # TextArea for notes.txt
        self.textArea = self.callbacks.createTextEditor()
        self.rightPane.setLeftComponent(self.textArea.getComponent())
        self.textArea.getComponent().addMouseListener(MouseClick(self))

        # rightPanel is a JPanel which contains the snip button and the Request/Response messageEditors
        self.rightPanel = swing.JPanel(BorderLayout())

        # Request/Response viewers
        self.tabReqResp = swing.JTabbedPane()
        self.tabReqResp.addMouseListener(MouseClick(self))
        self.requestViewer = self.callbacks.createMessageEditor(self, True)
        self.responseViewer = self.callbacks.createMessageEditor(self, True)
        self.editableFileTextViewer = self.callbacks.createTextEditor()
        # SET SELECTED ! 
        # Set listener for when Request/Response is changed
        self.requestViewer.getComponent().addMouseListener(MouseClick(self))
        self.responseViewer.getComponent().addMouseListener(MouseClick(self))

        # Set listener for when the user clicks inside a Raw Request/Response

        self.tabReqResp.addTab("Request", self.requestViewer.getComponent())
        self.tabReqResp.addTab("Response", self.responseViewer.getComponent())
        self.tabReqResp.addTab("Text editor", self.editableFileTextViewer.getComponent())

        self.editableFileTextViewer.setEditable(False)
        # Create a panel which holds the SNIP buttons
        self.snipButtonPanel = swing.JPanel(GridLayout(1, 2))

        # Add button to snip everything but selection
        self.btnIncludeSelection = swing.JButton("Include selected data")
        self.btnIncludeSelection.setPreferredSize(Dimension(1, 30))
        self.btnIncludeSelection.addActionListener(handlers.HandleIncludeSelection(self))
        self.snipButtonPanel.add(self.btnIncludeSelection)

        # Add button to snip certain things
        self.btnExcludeSelection = swing.JButton("Exclude selected data")
        self.btnExcludeSelection.setPreferredSize(Dimension(1, 30))
        self.btnExcludeSelection.addActionListener(handlers.HandleExcludeSelection(self))
        self.snipButtonPanel.add(self.btnExcludeSelection)

        # Add button to reset the message
        self.revertButtonPane = swing.JPanel(GridLayout(2, 1))
        self.btnRevertMessage = swing.JButton("Revert to original")
        self.btnRevertMessage.setPreferredSize(Dimension(1, 30))
        self.btnRevertMessage.addActionListener(handlers.HandleRevertMessage(self))

        # Add components in one pane, this ensures that incl. & excl. are next to each other and revert is at the bottom
        self.revertButtonPane.add(self.snipButtonPanel)
        self.revertButtonPane.add(self.btnRevertMessage)

        # Add Components to rightPanel
        self.rightPanel.add(self.tabReqResp)
        self.rightPanel.add(self.revertButtonPane, BorderLayout.PAGE_END)
        

        self.rightPane.setRightComponent(self.rightPanel)

        # Create leftPane, split into top and bottom.
        # leftTop is a table with all the findings, leftBottom is for the files
        self.leftPaneTop = swing.JPanel()
        self.leftPaneTop.setLayout(swing.BoxLayout(self.leftPaneTop, swing.BoxLayout.Y_AXIS))
        self.leftPaneBottom = swing.JPanel()
        self.leftPaneBottom.setLayout(BorderLayout())
        
        # Create the custom model for the tables
        self.tableModelFindings = TableModelFindings(self)
        self.tableModelEvidences = TableModelEvidences(self)

        # Create a pane which holds the table findings with the custom model
        self.paneTableFindings = swing.JScrollPane(self.tableModelFindings.getTable())
        self.paneTableFindings.setPreferredSize(Dimension(1, 300))
        self.paneTableFindings.setAlignmentX(swing.JPanel.LEFT_ALIGNMENT)

        # Create a pane which holds the table evidences with the custom model
        self.paneTableEvidences = swing.JScrollPane(self.tableModelEvidences.getTable())
        self.paneTableEvidences.setPreferredSize(Dimension(1, 300))
        self.paneTableEvidences.setAlignmentX(swing.JPanel.LEFT_ALIGNMENT)

        # Create some labels
        labelFindings = swing.JLabel("Findings:")
        labelFindings.setAlignmentX(swing.JLabel.LEFT_ALIGNMENT)

        labelEvidenceFiles = swing.JLabel("Evidence Files:")
        labelEvidenceFiles.setAlignmentX(swing.JLabel.LEFT_ALIGNMENT)

        # Add the objects to the panes
        self.leftPaneTop.add(labelFindings)
        self.leftPaneTop.add(self.paneTableFindings)


        self.leftPaneBottom.add(labelEvidenceFiles)
        self.leftPaneBottom.add(self.paneTableEvidences)

        # TODO : add screenshot buttons here
        ### CODE - START


        # Add button to snip everything but selection

        self.fileEvidenceButtons = swing.JPanel(GridLayout(2, 1))

        self.btnAddFileEvidence = swing.JButton("Add file evidence")
        self.btnAddFileEvidence.setPreferredSize(Dimension(1, 20))
        self.btnAddFileEvidence.addActionListener(handlers.HandleNewFileEvidence(self))
        self.fileEvidenceButtons.add(self.btnAddFileEvidence)

        self.btnAddEditableTextEvidence = swing.JButton("Add editable text evidence")
        self.btnAddEditableTextEvidence.setPreferredSize(Dimension(1, 20))
        self.btnAddEditableTextEvidence.addActionListener(handlers.HandleNewEditableTextEvidence(self))
        self.fileEvidenceButtons.add(self.btnAddEditableTextEvidence)

        # Add components in one pane, this ensures that incl. & excl. are next to each other and revert is at the bottom
        self.leftPaneBottom.add(self.fileEvidenceButtons, BorderLayout.PAGE_END)

        ### CODE - END

        self.leftPane.add(self.leftPaneTop)
        self.leftPane.add(self.leftPaneBottom)

        self.tabOverview.setLeftComponent(self.leftPane)
        self.tabOverview.setRightComponent(self.rightPane)

    def createTabImportExport(self):
        """This tab is where the user can export the findings/evidences"""

        self.tabIExport = swing.JPanel()
        self.tabIExport.setLayout(None)

        self.findingPrefixLabel = swing.JLabel("Finding ID prefix: ")
        self.findingPrefixLabel.setBounds(40, 30, 200, 30)

        self.findingPrefixText = swing.JTextField("")
        self.findingPrefixText.setBounds(40, 60, 100, 30)
        self.findingPrefixText.setText("A")

        self.selectPathLabel = swing.JLabel("Location: ")
        self.selectPathLabel.setBounds(40, 30 + 60, 200, 30)

        self.selectPathText = swing.JTextField("")
        self.selectPathText.setBounds(40, 60 + 60, 510, 30)
        self.selectPathText.getDocument().addDocumentListener(TextBoxListener(self))

        self.selectPath = swing.JButton("Select path ")
        self.selectPath.addActionListener(handlers.HandleSelectPath(self, self.selectPathText))
        self.selectPath.setBounds(40 + 530, 60 + 60, 120, 30)

        self.saveButton = swing.JButton("Export  ")
        self.saveButton.addActionListener(handlers.HandleSaveButton(self, self.selectPathText, self.findingPrefixText))
        self.saveButton.setBounds(40 + 305, 95 + 60, 100, 30)

        self.loadButton = swing.JButton("Import  ")
        self.loadButton.addActionListener(handlers.HandleLoadButton(self, self.selectPathText))
        self.loadButton.setBounds(40 + 410, 95 + 60, 100, 30)

        self.otherLabel2 = swing.JLabel("Other: ")
        self.otherLabel2.setBounds(40, 200, 120, 30)

        self.autoSaveOption = swing.JCheckBox("Auto save periodically ")
        self.autoSaveOption.setSelected(False)
        self.autoSaveOption.addActionListener(
            handlers.HandleAutoSaveOption(self, self.selectPathText, self.findingPrefixText)
        )
        self.autoSaveOption.setBounds(40, 200 + 20, 150, 30)

        self.recoveryButton = swing.JButton("Try recovery")
        self.recoveryButton.addActionListener(handlers.HandleRecoveryButton(self))
        self.recoveryButton.setBounds(40, 200 + 60, 120, 30)

        self.tabIExport.add(self.findingPrefixLabel)
        self.tabIExport.add(self.findingPrefixText)
        self.tabIExport.add(self.selectPathLabel)
        self.tabIExport.add(self.selectPathText)
        self.tabIExport.add(self.selectPath)
        self.tabIExport.add(self.saveButton)
        self.tabIExport.add(self.loadButton)
        self.tabIExport.add(self.otherLabel2)
        self.tabIExport.add(self.autoSaveOption)
        self.tabIExport.add(self.recoveryButton)

    def createTabConfiguration(self):
        """The tabConfiguration lets the user customize the behaviour of the plugin"""

        mainPanel = swing.JPanel()
        mainPanel.setLayout(None)
        mainPanel.setPreferredSize(Dimension(700, 1200))

        self.addHeaderSnipping(mainPanel)
        self.addCustomNotesTemplate(mainPanel)
        self.addCustomEvidenceTemplate(mainPanel)
        self.addCustomFileNames(mainPanel)

        self.tabConfiguration = swing.JScrollPane(mainPanel)

    def addHeaderSnipping(self, parentPanel):
        baseX, baseY = 30, 10

        labelTitle = swing.JLabel("Header processing")
        labelTitle.setForeground(Color(0xff6633))
        labelTitle.setFont(Font("Nimbus", Font.BOLD, 13))
        labelTitle.setBounds(baseX, baseY, 300, 20)
        parentPanel.add(labelTitle)

        labelInfo = swing.JLabel("Which headers should be automatically snipped/redacted?")
        labelInfo.setBounds(baseX, baseY + 20, 800, 30)
        parentPanel.add(labelInfo)

        # The button which allows to add rules
        btnAddRule = swing.JButton("Add")
        btnAddRule.setPreferredSize(Dimension(1, 30))
        btnAddRule.addActionListener(handlers.HandleAddRule(self))
        btnAddRule.setBounds(baseX, baseY + 70, 80, 30)
        parentPanel.add(btnAddRule)

        # Add the button which allows to delete rules
        btnDeleteRule = swing.JButton("Delete")
        btnDeleteRule.setPreferredSize(Dimension(1, 30))
        btnDeleteRule.addActionListener(handlers.HandleDeleteRule(self))
        btnDeleteRule.setBounds(baseX, baseY + 105, 80, 30)
        parentPanel.add(btnDeleteRule)

        self.tableModelRules = TableModelRules(self)
        paneTableRules = swing.JScrollPane(self.tableModelRules.getTable())
        paneTableRules.setPreferredSize(Dimension(1, 200))
        paneTableRules.setBounds(baseX + 90, baseY + 70, 500, 200)
        parentPanel.add(paneTableRules)

        horizontalRule = swing.JSeparator()
        horizontalRule.setBounds(baseX - 20, baseY + 290, 800, 5)
        parentPanel.add(horizontalRule)

    def addCustomNotesTemplate(self, parentPanel):
        baseX, baseY = 40, 330

        labelTitle = swing.JLabel("Notes template")
        labelTitle.setForeground(Color(0xff6633))
        labelTitle.setBounds(baseX, baseY, 200, 20)  # x, y, width, height
        labelTitle.setFont(Font("Nimbus", Font.BOLD, 13))
        parentPanel.add(labelTitle)

        labelInfo = swing.JLabel("What should be added to the notes when a Finding/Evidence is added?")
        labelInfo.setBounds(baseX, baseY + 30, 600, 20)  # x, y, width, height
        parentPanel.add(labelInfo)

        self.textAreaNotesTemplate = self.callbacks.createTextEditor()
        self.textAreaNotesTemplate.getComponent().setBounds(baseX + 120, baseY + 75, 450, 200)  # x, y, width, height
        parentPanel.add(self.textAreaNotesTemplate.getComponent())

        self.notesFindingTemplate = ""
        self.notesEvidenceTemplate = ""
        self.comboboxNotesOptionsChangedManually = True
        previousIndex = 0

        array = ["Finding", "Evidence"]
        self.comboboxNotesType = swing.JComboBox(ArrayList(array))
        self.comboboxNotesType.setSelectedIndex(0)
        self.comboboxNotesType.addActionListener(handlers.HandleTemplateNotesChangeType(self, labelInfo, previousIndex))
        self.comboboxNotesType.setBounds(baseX, baseY + 75, 110, 25)
        parentPanel.add(self.comboboxNotesType)

        array = ["NAME", "SEVERITY"]
        self.comboboxNotesOptions = swing.JComboBox(ArrayList(array))
        self.comboboxNotesOptions.setBounds(baseX, baseY + 105, 110, 25)
        self.comboboxNotesOptions.addActionListener(handlers.HandleTemplateNotesAddOption(self))
        parentPanel.add(self.comboboxNotesOptions)

        buttonSave = swing.JButton("Save")
        buttonSave.setBounds(baseX, baseY + 185, 100, 30)
        buttonSave.addActionListener(handlers.HandleSaveNotesTemplate(self))
        parentPanel.add(buttonSave)
        
        buttonClear = swing.JButton("Clear")
        buttonClear.setBounds(baseX, baseY + 215, 100, 30)
        buttonClear.addActionListener(handlers.HandleClearNotesTemplate(self))
        parentPanel.add(buttonClear)

        horizontalRule = swing.JSeparator()
        horizontalRule.setBounds(baseX - 20, baseY + 300, 800, 5)
        parentPanel.add(horizontalRule)

    def addCustomEvidenceTemplate(self, parentPanel):
        baseX = 40
        baseY = 650

        labelTitle = swing.JLabel("Evidence template")
        labelTitle.setForeground(Color(0xff6633))
        labelTitle.setBounds(baseX, baseY, 200, 20)  # x, y, width, height
        labelTitle.setFont(Font("Nimbus", Font.BOLD, 13))
        parentPanel.add(labelTitle)

        labelInfo = swing.JLabel("How should the exported Request/Response look like?")
        labelInfo.setBounds(baseX, baseY + 30, 600, 20)
        parentPanel.add(labelInfo)

        self.httpReqRespTemplate = ""

        self.textAreaHttpReqRespTemplate = self.callbacks.createTextEditor()
        self.textAreaHttpReqRespTemplate.getComponent().setBounds(baseX + 120, baseY + 75, 450, 200)
        parentPanel.add(self.textAreaHttpReqRespTemplate.getComponent())

        array = ["REQUEST", "RESPONSE"]
        self.comboboxTemplateHttpReqRespOptions = swing.JComboBox(ArrayList(array))
        self.comboboxTemplateHttpReqRespOptions.setBounds(baseX, baseY + 75, 110, 25)
        self.comboboxTemplateHttpReqRespOptions.addActionListener(handlers.HandleTemplateHttpReqRespAddOption(self))
        parentPanel.add(self.comboboxTemplateHttpReqRespOptions)

        buttonSave = swing.JButton("Save")
        buttonSave.setBounds(baseX, baseY + 185, 100, 30)
        buttonSave.addActionListener(handlers.HandleSaveHttpReqRespTemplate(self))
        parentPanel.add(buttonSave)

        buttonClear = swing.JButton("Clear")
        buttonClear.setBounds(baseX, baseY + 215, 100, 30)
        buttonClear.addActionListener(handlers.HandleClearHttpReqRespTemplate(self))
        parentPanel.add(buttonClear)

        horizontalRule = swing.JSeparator()
        horizontalRule.setBounds(baseX - 20, baseY + 300, 800, 5)
        parentPanel.add(horizontalRule)

    def addCustomFileNames(self, parentPanel):
        baseX = 40
        baseY = 970  # 510

        labelTitle = swing.JLabel("File names")
        labelTitle.setForeground(Color(0xff6633))
        labelTitle.setBounds(baseX, baseY, 200, 20)  # x, y, width, height
        labelTitle.setFont(Font("Nimbus", Font.BOLD, 13))
        parentPanel.add(labelTitle)

        labelInfo = swing.JLabel("How should the file containing the notes be named?")
        labelInfo.setBounds(baseX, baseY + 30, 400, 20)  # x, y, width, height
        parentPanel.add(labelInfo)

        self.textBoxNotesName = swing.JTextField()
        self.textBoxNotesName.setBounds(baseX, baseY + 55, 130, 28)  # x, y, width, height
        parentPanel.add(self.textBoxNotesName)

        labelEvidence = swing.JLabel("How should the files containing the evidences be named?")
        labelEvidence.setBounds(baseX, baseY + 90, 400, 20)  # x, y, width, height
        parentPanel.add(labelEvidence)

        self.textBoxEvidenceName = swing.JTextField()
        self.textBoxEvidenceName.setBounds(baseX, baseY + 110, 130, 28)  # x, y, width, height
        parentPanel.add(self.textBoxEvidenceName)

        saveButton = swing.JButton("Save")
        saveButton.setBounds(baseX, baseY + 150, 100, 30)
        saveButton.addActionListener(handlers.HandleSaveExportFileNames(self))
        parentPanel.add(saveButton)

    # implement ITab
    def getTabCaption(self):
        return "Evidence Collector"

    def getUiComponent(self):
        return self.parentPane

    # implement IMessageEditorController
    # currentlyDisplayedItem is an Evidence object - httpRequestResponse from serializable
    def getHttpService(self):
        return self.currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self.currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self.currentlyDisplayedItem.getResponse()

    # implement IContextMenuFactory
    def createMenuItems(self, invocation):
        """Adds the extension to the context menu that appears when you right-click an object."""
        itemContext = invocation.getSelectedMessages()

        # Only return a menu item if right clicking on a Message object
        if itemContext > 0:
            menuItem = ArrayList()
            collectorMenu = swing.JMenu("Evidence Collector")

            newFindingMenuItem = swing.JMenuItem("Create a new finding")
            addFindingMenuItem = swing.JMenuItem("Add to existing finding")

            collectorMenu.add(newFindingMenuItem)
            collectorMenu.add(addFindingMenuItem)

            # Call handleMenuItem with the Request/Response and a boolean indicating a new finding or not
            for item in itemContext:
                httpService = HttpService(item.getHttpService())
                httpRequestResponse = HttpRequestResponse(item)
                httpRequestResponse.setHttpService(httpService)

                newFindingMenuItem.addActionListener(handlers.HandleMenuItems(self, httpRequestResponse, True))
                addFindingMenuItem.addActionListener(handlers.HandleMenuItems(self, httpRequestResponse, False))

            menuItem.add(collectorMenu)
            return menuItem

    # implement IExtensionStateListener
    def extensionUnloaded(self):
        self.project = None
        sys.exit()

    def reset(self):
        self.tableModelFindings.reset()
        self.tableModelEvidences.reset()
        self.textArea.setText("")
        self.requestViewer.setMessage([0], True)
        self.responseViewer.setMessage([0], False)
