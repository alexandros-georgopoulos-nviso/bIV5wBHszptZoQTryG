from java.util import Comparator
from utils import risk_levels

class ComparatorSeverity(Comparator):
    """Custom Comparator which sorts the the tableFindings based on the Severity"""
    def __init__(self):
        self.severity = risk_levels

    def compare(self, s1, s2):
        i1 = self.severity.index(s1)
        i2 = self.severity.index(s2)

        if i1 < i2:
            return 1
        elif i1 > i2:
            return -1

        return 0


class ComparatorSeverityArrayList(Comparator):
    """Custom Comparator which sorts the findings objects in ArrayList based on severity"""
    def __init__(self):
        self.severity = risk_levels

    def compare(self, f1, f2):
        # f1 and f2 are Finding objects
        i1 = self.severity.index(f1.severity)
        i2 = self.severity.index(f2.severity)

        if i1 == i2:
            # https://docs.python.org/release/3.0.1/whatsnew/3.0.html#ordering-comparisons, Jython uses Python2.7
            return (f1.name > f2.name) - (f1.name < f2.name)
        elif i1 < i2:
            return 1
        else:
            return -1
