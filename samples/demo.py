# SYNTHETIC 教学样本，仅供扫描结果定位，不执行
def lookup(cursor, user):
    query = "SELECT * FROM users WHERE name='" + user + "'"
    return cursor.execute(query)

def render(raw):
    return "<div>" + raw + "</div>"

def load_yaml(text):
    return yaml.load(text, Loader=yaml.Loader)

def safe_lookup(cursor, user):
    return cursor.execute("SELECT * FROM users WHERE name=?", (user,))
