import string

def read_file(path):
    with open(path, "r") as f:
        return f.read()


def write_text_file(path, content):
    with open(path, "w+") as f:
        f.read()
        f.seek(0)
        f.write(content)
        f.truncate()

whitelist = string.ascii_letters + string.digits + '-_(). '
risk_levels = ["informational", "low ", "medium", "high", "critical"]