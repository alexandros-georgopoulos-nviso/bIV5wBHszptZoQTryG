class Rule:
    """The tableRules holds Rule objects"""

    enabled = False
    nameHeader = None

    def __init__(self, name, enabled=True):
        self.nameHeader = name
        self.enabled = enabled

    def equals(self, rule):
        if rule:
            return self.nameHeader == rule.nameHeader

        return False
