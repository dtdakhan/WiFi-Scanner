from PySide6.QtWidgets import QDialog, QPlainTextEdit, QPushButton, QVBoxLayout


class DiagnosticsDialog(QDialog):
    def __init__(self, text: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Chẩn đoán")
        self.resize(720, 520)
        lay = QVBoxLayout(self)
        self.view = QPlainTextEdit(text)
        self.view.setReadOnly(True)
        lay.addWidget(self.view)
        btn = QPushButton("Sao chép")
        btn.clicked.connect(lambda: self.view.selectAll() or self.view.copy())
        lay.addWidget(btn)
