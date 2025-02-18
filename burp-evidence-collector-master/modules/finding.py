from java.util import ArrayList
from java.io import Serializable

import re

class Finding(Serializable):
    """A finding has a severity, a name and an ArrayList of Evidences."""

    severity = None
    name = None
    evidences = ArrayList()

    def __init__(self, severity, name):
        self.severity = severity
        self.name = name

        self.evidences = ArrayList()

    def setSeverity(self, severity):
        self.severity = severity

    def setName(self, name):
        self.name = name

    def addEvidenceToFinding(self, evidence):
        self.evidences.add(evidence)
       
    def addNotesToFinding(self, notes):
        self.evidences.get(0).notes = notes

    def getNotes(self):
        return self.evidences.get(0).notes

    def removeEvidence(self, index):
        notes = self.evidences.get(0).notes
        evidence = self.evidences.get(index)

        startIndex = notes.index('- ' + evidence.name) - 1 # a newline character is added before each new evidence
        endIndex = notes.index('\n\n', startIndex) + 2

        evidenceNote = notes[startIndex:endIndex]
        notes = notes.replace(evidenceNote, '')

        matches = re.findall(r'evidence[0-9][0-9]', notes)
        for i, match in enumerate(matches, 1):
            count = str(i).zfill(2)
            notes = notes.replace(match, 'evidence' + count)

        self.evidences.get(0).notes = notes
        self.evidences.remove(index)

    def equals(self, finding):
        if finding:
            return self.severity == finding.severity and self.name == finding.name \
                   and self.evidences.equals(finding.evidences)

        return False
