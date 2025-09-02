"""
Dark theme styles for the application
"""

DARK_THEME = """
QMainWindow {
    background-color: #2b2b2b;
    color: #ffffff;
}

QTabWidget::pane {
    border: 1px solid #555555;
    background-color: #3c3c3c;
}

QTabWidget::tab-bar {
    left: 5px;
}

QTabBar::tab {
    background-color: #505050;
    color: #ffffff;
    padding: 8px 16px;
    margin-right: 2px;
    border: 1px solid #666666;
    border-bottom: none;
}

QTabBar::tab:selected {
    background-color: #3c3c3c;
    border-color: #888888;
}

QTabBar::tab:hover {
    background-color: #606060;
}

QTableWidget {
    background-color: #3c3c3c;
    alternate-background-color: #454545;
    color: #ffffff;
    gridline-color: #555555;
    border: 1px solid #666666;
}

QTableWidget::item {
    padding: 4px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #0078d4;
}

QHeaderView::section {
    background-color: #505050;
    color: #ffffff;
    padding: 6px;
    border: 1px solid #666666;
    font-weight: bold;
}

QPushButton {
    background-color: #0078d4;
    color: #ffffff;
    border: 1px solid #005a9e;
    padding: 6px 12px;
    border-radius: 3px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #106ebe;
}

QPushButton:pressed {
    background-color: #005a9e;
}

QPushButton:disabled {
    background-color: #505050;
    color: #888888;
    border-color: #666666;
}

QMenuBar {
    background-color: #2b2b2b;
    color: #ffffff;
    border-bottom: 1px solid #555555;
}

QMenuBar::item {
    background-color: transparent;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #0078d4;
}

QMenu {
    background-color: #3c3c3c;
    color: #ffffff;
    border: 1px solid #666666;
}

QMenu::item {
    padding: 4px 20px;
}

QMenu::item:selected {
    background-color: #0078d4;
}

QStatusBar {
    background-color: #2b2b2b;
    color: #ffffff;
    border-top: 1px solid #555555;
}

QProgressBar {
    border: 1px solid #666666;
    border-radius: 3px;
    text-align: center;
    background-color: #3c3c3c;
    color: #ffffff;
}

QProgressBar::chunk {
    background-color: #0078d4;
    border-radius: 2px;
}

QLabel {
    color: #ffffff;
}

QLineEdit {
    background-color: #3c3c3c;
    color: #ffffff;
    border: 1px solid #666666;
    padding: 4px;
    border-radius: 3px;
}

QLineEdit:focus {
    border-color: #0078d4;
}

QComboBox {
    background-color: #3c3c3c;
    color: #ffffff;
    border: 1px solid #666666;
    padding: 4px;
    border-radius: 3px;
}

QComboBox::drop-down {
    border: none;
    background-color: #505050;
}

QComboBox::down-arrow {
    border: 2px solid #ffffff;
    border-top: none;
    border-right: none;
    width: 6px;
    height: 6px;
}

QCheckBox {
    color: #ffffff;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
}

QCheckBox::indicator:unchecked {
    background-color: #3c3c3c;
    border: 1px solid #666666;
}

QCheckBox::indicator:checked {
    background-color: #0078d4;
    border: 1px solid #005a9e;
}

QGroupBox {
    color: #ffffff;
    border: 1px solid #666666;
    border-radius: 3px;
    margin-top: 10px;
    padding-top: 10px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px 0 5px;
}

QTextEdit {
    background-color: #3c3c3c;
    color: #ffffff;
    border: 1px solid #666666;
    border-radius: 3px;
}

QScrollBar:vertical {
    background-color: #3c3c3c;
    width: 12px;
    border: 1px solid #666666;
}

QScrollBar::handle:vertical {
    background-color: #606060;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #707070;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    background: none;
}

QScrollBar:horizontal {
    background-color: #3c3c3c;
    height: 12px;
    border: 1px solid #666666;
}

QScrollBar::handle:horizontal {
    background-color: #606060;
    min-width: 20px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #707070;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    border: none;
    background: none;
}
"""