import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QWidget, QFrame, QStackedWidget, QComboBox
)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import random


class TrafficInsightsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(self.create_layout())

    def create_layout(self):
        layout = QVBoxLayout()

        # Dropdown to switch between charts
        self.chart_selector = QComboBox()
        self.chart_selector.addItems(["Bar Chart", "Pie Chart"])
        self.chart_selector.currentIndexChanged.connect(self.update_chart)
        layout.addWidget(self.chart_selector)

        # Stacked widget to switch between graph views
        self.graphs = QStackedWidget()
        self.bar_chart = self.create_bar_chart()
        self.pie_chart = self.create_pie_chart()

        self.graphs.addWidget(self.bar_chart)
        self.graphs.addWidget(self.pie_chart)

        layout.addWidget(self.graphs)
        return layout

    def create_bar_chart(self):
        figure, ax = plt.subplots()
        ax.bar(["USA", "India", "China", "Germany"], [random.randint(10, 100) for _ in range(4)])
        ax.set_title("Traffic Insights (Bar Chart)")
        canvas = FigureCanvas(figure)
        return canvas

    def create_pie_chart(self):
        figure, ax = plt.subplots()
        data = [random.randint(10, 100) for _ in range(4)]
        ax.pie(data, labels=["USA", "India", "China", "Germany"], autopct="%1.1f%%")
        ax.set_title("Traffic Insights (Pie Chart)")
        canvas = FigureCanvas(figure)
        return canvas

    def update_chart(self):
        index = self.chart_selector.currentIndex()
        self.graphs.setCurrentIndex(index)


class MainPage(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Server Monitoring Dashboard")
        self.setGeometry(100, 100, 1200, 700)
        self.set_dark_theme()

        # Central widget layout
        self.central_widget = QWidget()
        self.central_layout = QVBoxLayout(self.central_widget)

        # Top navigation bar
        self.navbar = self.create_navbar()
        self.central_layout.addWidget(self.navbar)

        # Main content area
        self.pages = QStackedWidget()
        self.pages.addWidget(self.create_home_page())
        self.pages.addWidget(self.create_firewall_page())
        self.pages.addWidget(self.create_files_page())
        self.pages.addWidget(self.create_jail_page())
        self.central_layout.addWidget(self.pages)

        self.setCentralWidget(self.central_widget)

        # Set Home page as default
        self.pages.setCurrentIndex(0)

    def create_navbar(self):
        navbar = QFrame()
        navbar.setStyleSheet("background-color: #121212; padding: 10px;")
        navbar_layout = QHBoxLayout(navbar)

        # Navigation buttons
        self.home_btn = QPushButton("Home")
        self.firewall_btn = QPushButton("Firewall")
        self.files_btn = QPushButton("Files")
        self.jail_btn = QPushButton("Jail")

        for button in [self.home_btn, self.firewall_btn, self.files_btn, self.jail_btn]:
            button.setStyleSheet("color: white; background-color: #1E1E1E; padding: 5px 15px;")
            button.setFont(QFont("Arial", 12))
            button.clicked.connect(self.handle_navbar_click)
            navbar_layout.addWidget(button)

        navbar_layout.addStretch()
        return navbar

    def handle_navbar_click(self):
        sender = self.sender()
        if sender == self.home_btn:
            self.pages.setCurrentIndex(0)
        elif sender == self.firewall_btn:
            self.pages.setCurrentIndex(1)
        elif sender == self.files_btn:
            self.pages.setCurrentIndex(2)
        elif sender == self.jail_btn:
            self.pages.setCurrentIndex(3)

    def create_home_page(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #1E1E1E;")
        layout = QHBoxLayout(frame)

        # Left section: Real-time notifications
        left_frame = self.create_left_frame()

        # Right section: Traffic insights
        right_frame = TrafficInsightsPage()

        layout.addWidget(left_frame, 1)
        layout.addWidget(right_frame, 3)
        return frame

    def create_firewall_page(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #1E1E1E;")
        layout = QVBoxLayout(frame)

        label = QLabel("Firewall Management")
        label.setFont(QFont("Arial", 16))
        label.setStyleSheet("color: white;")
        layout.addWidget(label)

        layout.addStretch()
        return frame

    def create_files_page(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #1E1E1E;")
        layout = QVBoxLayout(frame)

        label = QLabel("File Management")
        label.setFont(QFont("Arial", 16))
        label.setStyleSheet("color: white;")
        layout.addWidget(label)

        layout.addStretch()
        return frame

    def create_jail_page(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #1E1E1E;")
        layout = QVBoxLayout(frame)

        label = QLabel("Jail Monitoring and Management")
        label.setFont(QFont("Arial", 16))
        label.setStyleSheet("color: white;")
        layout.addWidget(label)

        layout.addStretch()
        return frame

    def create_left_frame(self):
        frame = QFrame()
        frame.setStyleSheet("background-color: #252526; border: 1px solid #333;")
        layout = QVBoxLayout(frame)

        title = QLabel("Real-Time Notifications")
        title.setFont(QFont("Arial", 14))
        title.setStyleSheet("color: white;")
        layout.addWidget(title)

        notifications = QLabel("• Server started successfully.\n• High traffic detected from 192.168.1.5\n• New connection from China.")
        notifications.setStyleSheet("color: lightgray; font-size: 12px;")
        layout.addWidget(notifications)

        layout.addStretch()
        return frame

    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#121212"))
        palette.setColor(QPalette.WindowText, QColor("white"))
        palette.setColor(QPalette.Base, QColor("#1E1E1E"))
        palette.setColor(QPalette.AlternateBase, QColor("#121212"))
        palette.setColor(QPalette.ToolTipBase, QColor("white"))
        palette.setColor(QPalette.ToolTipText, QColor("white"))
        palette.setColor(QPalette.Text, QColor("white"))
        palette.setColor(QPalette.Button, QColor("#1E1E1E"))
        palette.setColor(QPalette.ButtonText, QColor("white"))
        palette.setColor(QPalette.Highlight, QColor("#BB86FC"))
        palette.setColor(QPalette.HighlightedText, QColor("black"))
        self.setPalette(palette)


def main():
    app = QApplication(sys.argv)
    main_window = MainPage()
    main_window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
