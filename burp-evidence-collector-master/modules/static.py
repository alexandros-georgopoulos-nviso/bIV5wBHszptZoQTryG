from javax import swing
from java.awt import Frame

import re
from unicodedata import normalize

global _punct_re
_punct_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.:]+')


class Static:
    def __init__(self):
        pass

    @staticmethod
    def getBurpFrame():
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
                return frame

    @staticmethod
    def showError(title, message):
        swing.JOptionPane.showMessageDialog(Static.getBurpFrame(), message, title, swing.JOptionPane.ERROR_MESSAGE)

    @staticmethod
    def showWarning(title, message):
        swing.JOptionPane.showMessageDialog(Static.getBurpFrame(), message, title, swing.JOptionPane.WARNING_MESSAGE)

    @staticmethod
    def recurseRemove(directory):
        # Delete all files in the directory, then remove the directory
        if directory.isDirectory():
            files = directory.listFiles()
            if files:
                for f in files:
                    Static.recurseRemove(f)

        directory.delete()

    @staticmethod
    def slugify(text, delim=u'-'):
        """Generates an slightly worse ASCII-only slug. --> Downside is that it's all lowercase
        https://stackoverflow.com/questions/9042515/normalizing-unicode-text-to-filenames-etc-in-python"""
        result = []
        for word in _punct_re.split(text.lower()):
            word = normalize('NFKD', word).encode('ascii', 'ignore')
            if word:
                result.append(word)
        return unicode(delim.join(result))
