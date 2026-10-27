STYLE = """
QMainWindow, QWidget { font-size: 13px; }
#title { font-size: 20px; font-weight: 600; }
#muted { color: #6b7280; }
#banner { padding: 8px 10px; border-radius: 6px; background: #fff7e0; color: #7a5b00; }
#banner[level="error"] { background: #fde8e8; color: #9b1c1c; }
#banner[level="ok"] { background: #e6f4ea; color: #1e6b34; }
QFrame#card { border: 1px solid #e5e7eb; border-radius: 6px; background: #ffffff; }
QLabel#cardValue { font-size: 13px; font-weight: 700; color: #111827; }
QLabel#cardCaption { color: #6b7280; font-size: 12px; }
QPushButton { padding: 6px 14px; border-radius: 6px; border: 1px solid #c4c9d1; }
QPushButton:default, QPushButton#primary { background: #2563eb; color: white; border-color: #2563eb; }
QPushButton:disabled { background: #e5e7eb; color: #9ca3af; border-color: #e5e7eb; }
QTableView { gridline-color: #e5e7eb; alternate-background-color: #f8fafc; selection-background-color: #dbeafe;
             selection-color: #111827; }
QHeaderView::section { padding: 5px; font-weight: 600; }
"""
LEVEL_COLORS = {"strong": "#15803d", "medium": "#b45309", "weak": "#b91c1c"}
