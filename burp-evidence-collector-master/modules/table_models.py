from abc import abstractmethod
from javax import swing
from javax.swing.table import AbstractTableModel, TableRowSorter
from java.util import ArrayList

from tables import TableFindings, TableEvidences, TableRules
from evidence import Evidence
from finding import Finding
from rule import Rule
from comparators import ComparatorSeverity
from static import Static
from utils import whitelist, risk_levels


class TableModelFindings(AbstractTableModel):
    """The tableModel used for the tableFindings - It defines the layout of the table"""

    findings = ArrayList()
    columnNames = ["Severity", "Name"]

    def __init__(self, extender):
        self.extender = extender
        self.findings = extender.project.findings

        self.tableFindings = TableFindings(self)

        # self.tableFindings.setAutoCreateRowSorter(True)
        self.tableFindings.setRowSelectionAllowed(True)

        self.tableFindings.getColumn("Severity").setPreferredWidth(100)
        self.tableFindings.getColumn("Severity").setMaxWidth(120)

        self.setUpSeverityColumn()

    def getTable(self):
        return self.tableFindings

    def reset(self):
        """Reset the tableFindings"""
        self.extender.project.findings = ArrayList()
        self.findings = self.extender.project.findings

        self.tableFindings.currentFindingEntry = -1
        self.tableFindings.nextFindingEntry = -1
        self.fireTableDataChanged()

    def setFindings(self, findings):
        # set the findings to display in the tableFindings
        # When findings are set, there is no previous finding or evidence to save (saveEvidences())
        self.tableFindings.currentFindingEntry = -1
        self.extender.tableModelEvidences.getTable().currentEvidenceEntry = -1

        self.findings = findings
        self.fireTableDataChanged()
        self.tableFindings.changeSelection(0, 1, False, False)

    def setUpSeverityColumn(self):
        """Set 'severity' values in a JComboBox"""
        columnIndex = 0
        severityColumn = self.getTable().getColumnModel().getColumn(columnIndex)
        comboBox = swing.JComboBox(risk_levels)
        comboBox.addActionListener(self.listener)
        severityColumn.setCellEditor(swing.DefaultCellEditor(comboBox))

    def listener(self, l):
        self.fireTableDataChanged()

    def addFindingEntry(
        self, severity, nameFinding, messageInfo, nameEvidence, details, evidenceType, templateName="default", filePath=""
    ):
        """Create a new finding and add it to tableModelFindings"""
        entry = Finding(severity, nameFinding)
        entry.addEvidenceToFinding(
            Evidence(
                None,
                self.extender.project.notesFileName,
                "Notepad",
                Evidence.NON_EDITABLE_FILE,
                filePath=filePath,
                content="", # should probably change that line
                filePathExtraFile="empty",
            )
        )
        evidence = Evidence(
            messageInfo,
            nameEvidence,
            details,
            evidenceType=evidenceType,
            filePath=filePath,
            content="",
            filePathExtraFile="empty",
        )

        # Create the notes
        self.extender.project.addNotesToFinding(entry, evidence, False, templateName)
        self.extender.project.addNotesToFinding(entry, evidence, True)

        # Add the Finding and Evidence to the Project
        self.extender.project.addFinding(entry)
        self.extender.project.addEvidence(entry, evidence)

        # https://docs.oracle.com/javase/7/docs/api/javax/swing/table/AbstractTableModel.html#fireTableRowsInserted(int,int)
        row = self.findings.indexOf(entry)

        self.fireTableRowsInserted(row, row)

        # If this is the first finding entry that is added, select it.
        if self.tableFindings.currentFindingEntry == -1 and len(self.findings) == 1:
            self.tableFindings.changeSelection(0, 1, False, False)

    def removeFindingEntry(self, indexFinding):
        """Remove the finding from the ArrayList"""
        self.extender.project.removeFinding(indexFinding)

    def getRowCount(self):
        return self.findings.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        findingEntry = self.findings.get(rowIndex)
        if columnIndex == 0:
            return findingEntry.severity
        if columnIndex == 1:
            return findingEntry.name
        return ""

    def setValueAt(self, aValue, rowIndex, columnIndex):
        if columnIndex == 0:
            self.findings.get(rowIndex).severity = aValue
        if columnIndex == 1:
            # Strip unnecessary spaces
            aValue = aValue.strip()

            # If it contains something NOT in the whitelist it is an invalid name
            for c in aValue:
                if c not in whitelist:
                    return

            # Change the finding name
            modelRow = self.getTable().convertRowIndexToModel(rowIndex)
            finding = self.findings.get(modelRow)
            self.extender.project.changeFindingName(finding, aValue, self.extender)

    def isCellEditable(self, row, col):
        return True

    def tableChanged(self, e):
        self.fireTableDataChanged()


class TableModelEvidences(AbstractTableModel):
    """The tableModel used for tableEvidences - It defines the layout of the table"""

    evidences = ArrayList()
    columnNames = ["Names", "Type"]

    def __init__(self, extender):
        self.extender = extender
        self.tableEvidences = TableEvidences(self)
        # self.tableEvidences.setAutoCreateRowSorter(True)
        self.tableEvidences.setRowSelectionAllowed(True)

        # self.tableEvidences.getColumn("Name").setPreferredWidth(100)
        # self.tableEvidences.getColumn("Name").setMaxWidth(120)

    def getTable(self):
        return self.tableEvidences

    def reset(self):
        """Reset the tableEvidences"""
        self.evidences = ArrayList()
        self.tableEvidences.currentEvidenceEntry = -1
        self.tableEvidences.nextEvidenceEntry = -1
        self.fireTableDataChanged()

    def addEvidenceEntry(self, finding, messageInfo, nameEvidence, details, evidenceType, filePath="", **filePathExtraFile):
        """Add evidence to the finding and update tableModelEvidences to show the recent added evidence entry"""
        # Add Evidence to the Project

        evidence = Evidence(
            messageInfo,
            nameEvidence,
            details,
            evidenceType=evidenceType,
            filePath=filePath,
            content="",
            filePathExtraFile=filePathExtraFile,
        )
        self.extender.project.addNotesToFinding(finding, evidence, True)
        self.extender.project.addEvidence(finding, evidence)

        # If the current open finding equals the finding to which the notes were added then update the textArea
        if self.extender.tableModelFindings.tableFindings.currentFindingEntry == finding:
            self.extender.textArea.setText(finding.getNotes())

            # Update the tableModelEvidences to show the newly created evidence
            rowIndex = len(self.evidences) - 1
            self.fireTableRowsInserted(rowIndex, rowIndex)

    def removeEvidenceEntry(self, indexFinding, indexEvidence):
        """Remove the finding from the ArrayList"""
        self.extender.project.removeEvidence(indexFinding, indexEvidence)

        finding = self.extender.project.findings.get(indexFinding)

        if self.extender.tableModelFindings.tableFindings.currentFindingEntry == finding:
            self.extender.textArea.setText(finding.getNotes())

            rowIndex = len(self.evidences) - 1
            # self.fireTableRowsInserted(rowIndex, rowIndex)
            self.fireTableRowsDeleted(indexEvidence, indexEvidence)

    def setEvidences(self, evidences):
        """Update evidences and redraw the table"""
        self.evidences = evidences
        self.fireTableDataChanged()

    def getEvidences(self):
        return self.evidences

    def getRowCount(self):
        return self.evidences.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        evidenceEntry = self.evidences.get(rowIndex)
        if columnIndex == 0:
            return evidenceEntry.name
        if columnIndex == 1:
            if evidenceEntry.evidenceType == Evidence.NON_EDITABLE_FILE:
                return "File"
            elif evidenceEntry.evidenceType == Evidence.EDITABLE_TEXT_FILE:
                return "Text"
            else:
                return "Request/Response"
        return ""

    def setValueAt(self, aValue, rowIndex, columnIndex):
        if columnIndex == 0:
            # Strip unnecessary spaces
            aValue = aValue.strip()

            # If it contains something NOT in the whitelist it is an invalid name
            for c in aValue:
                if c not in whitelist:
                    return

            # Evidence file cannot have an empty name
            if len(aValue) < 1:
                return

            # If duplicate name, don't change it
            for evidence in self.evidences:
                if evidence.name == aValue:
                    Static.showWarning("Warning!", "Evidence files can't have duplicate names!")
                    return

            # Change the evidence name
            modelRow = self.getTable().convertRowIndexToModel(rowIndex)
            evidence = self.evidences.get(modelRow)
            finding = self.extender.tableModelFindings.getTable().currentFindingEntry
            self.extender.project.changeEvidenceName(finding, evidence, aValue)

        if columnIndex == 1:
            self.evidences.get(rowIndex).details = aValue

    def isCellEditable(self, row, col):
        if row == 0 and col == 0:
            return False

        return False


class TableModelRules(AbstractTableModel):
    """The tableModel used for tableRules - It defines the layout of the table"""

    rules = ArrayList()
    columnNames = ["Enabled", "Rule"]

    def __init__(self, extender):
        self.extender = extender
        self.rules = extender.project.rules
        self.tableRules = TableRules(self)

        self.setUpRulesColumn()

        self.tableRules.getColumn("Enabled").setMinWidth(80)
        self.tableRules.getColumn("Enabled").setMaxWidth(80)

    def getTable(self):
        return self.tableRules

    def reset(self):
        """Reset the tableRules"""
        self.extender.project.rules = ArrayList()
        self.rules = self.extender.project.rules

        self.fireTableDataChanged()

    def addRuleEntry(self, value):
        entry = Rule(value)

        # Check if the rule already exists
        if len(self.rules) > 0:
            for r in self.rules:
                if entry.equals(r):
                    Static.showWarning("Duplicate!", "This rule already exists")
                    return

        self.extender.project.rules.add(entry)

        row = self.rules.indexOf(entry)
        self.fireTableRowsInserted(row, row)

    def deleteRuleEntry(self, indexRule):
        """Remove the finding from the ArrayList"""
        self.extender.project.rules.remove(indexRule)
        self.fireTableRowsDeleted(indexRule, indexRule)

    def setUpRulesColumn(self):
        """Set 'True/False' values in a JComboBox"""
        ruleIndex = 0
        rulesColumn = self.getTable().getColumnModel().getColumn(ruleIndex)
        comboBox = swing.JComboBox([True, False])
        rulesColumn.setCellEditor(swing.DefaultCellEditor(comboBox))

    def setRules(self, rules):
        """Update evidences and redraw the table"""
        self.rules = rules
        self.fireTableDataChanged()

    def getRules(self):
        return self.rules

    def getRowCount(self):
        return self.rules.size()

    def getColumnCount(self):
        return len(self.columnNames)

    def getColumnName(self, columnIndex):
        return self.columnNames[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        rulesEntry = self.rules.get(rowIndex)
        if columnIndex == 0:
            return rulesEntry.enabled
        if columnIndex == 1:
            return rulesEntry.nameHeader
        return ""

    def setValueAt(self, aValue, rowIndex, columnIndex):
        if columnIndex == 0:
            self.rules.get(rowIndex).enabled = aValue

        if columnIndex == 1:
            self.rules.get(rowIndex).rule = Static.slugify(aValue)

    def isCellEditable(self, row, col):
        return True
