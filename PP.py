import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget, QTableWidgetItem, QHBoxLayout, QComboBox
)
import psycopg2
from datetime import datetime, timedelta

def get_db_connection():
    return psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="qwerty",
        host="localhost",
        port="5432"
    )

class LoginForm(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Авторизация")
        layout = QVBoxLayout()

        self.login_label = QLabel("Логин:")
        self.login_input = QLineEdit()
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.handle_login)

        layout.addWidget(self.login_label)
        layout.addWidget(self.login_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def handle_login(self):
        login = self.login_input.text()
        password = self.password_input.text()

        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Все поля обязательны для заполнения.")
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, role, password, failed_attempts, last_login, is_blocked FROM users WHERE login = %s", (login,))
            user = cursor.fetchone()

            if not user:
                QMessageBox.warning(self, "Ошибка", "Вы ввели неверный логин или пароль. Пожалуйста проверьте ещё раз введенные данные.")
                return

            user_id, role, db_password, failed_attempts, last_login, is_blocked = user

            if is_blocked:
                QMessageBox.warning(self, "Ошибка", "Вы заблокированы. Обратитесь к администратору.")
                return

            if db_password != password:
                failed_attempts += 1
                if failed_attempts >= 3:
                    cursor.execute("UPDATE users SET is_blocked = TRUE WHERE id = %s", (user_id,))
                    conn.commit()
                    QMessageBox.warning(self, "Ошибка", "Вы заблокированы. Обратитесь к администратору.")
                else:
                    cursor.execute("UPDATE users SET failed_attempts = %s WHERE id = %s", (failed_attempts, user_id))
                    conn.commit()
                    QMessageBox.warning(self, "Ошибка", "Вы ввели неверный логин или пароль. Пожалуйста проверьте ещё раз введенные данные.")
                return

            cursor.execute("UPDATE users SET failed_attempts = 0, last_login = %s WHERE id = %s", (datetime.now(), user_id))
            conn.commit()

            QMessageBox.information(self, "Успех", "Вы успешно авторизовались.")

            if last_login is None:
                self.open_password_change_form(user_id)
            elif role == "Администратор":
                self.open_admin_dashboard()
            else:
                self.open_user_dashboard()

        finally:
            cursor.close()
            conn.close()

    def open_password_change_form(self, user_id):
        self.password_change_form = PasswordChangeForm(user_id)
        self.password_change_form.show()
        self.close()

    def open_admin_dashboard(self):
        self.admin_dashboard = AdminDashboard()
        self.admin_dashboard.show()
        self.close()

    def open_user_dashboard(self):
        QMessageBox.information(self, "Пользователь", "Добро пожаловать, Пользователь!")

class PasswordChangeForm(QWidget):
    def __init__(self, user_id):
        super().__init__()
        self.user_id = user_id
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Смена пароля")
        layout = QVBoxLayout()

        self.current_password_label = QLabel("Текущий пароль:")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)

        self.new_password_label = QLabel("Новый пароль:")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)

        self.confirm_password_label = QLabel("Подтверждение нового пароля:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        self.change_password_button = QPushButton("Изменить пароль")
        self.change_password_button.clicked.connect(self.handle_password_change)

        layout.addWidget(self.current_password_label)
        layout.addWidget(self.current_password_input)
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.change_password_button)

        self.setLayout(layout)

    def handle_password_change(self):
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not current_password or not new_password or not confirm_password:
            QMessageBox.warning(self, "Ошибка", "Все поля обязательны для заполнения.")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Новый пароль и подтверждение не совпадают.")
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT password FROM users WHERE id = %s", (self.user_id,))
            db_password = cursor.fetchone()[0]

            if db_password != current_password:
                QMessageBox.warning(self, "Ошибка", "Текущий пароль введен неверно.")
                return

            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (new_password, self.user_id))
            conn.commit()
            QMessageBox.information(self, "Успех", "Пароль успешно изменен.")
            self.close()

        finally:
            cursor.close()
            conn.close()

class AdminDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Панель администратора")
        layout = QVBoxLayout()

        # Настройка таблицы
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "Логин", "Пароль", "Роль", "Заблокирован", "Действия"])
        self.table.setAlternatingRowColors(True)  
        self.table.setStyleSheet("QTableWidget { gridline-color: #dcdcdc; }")  
        layout.addWidget(self.table)

        self.add_user_button = QPushButton("Добавить пользователя")
        self.add_user_button.setFixedHeight(40)  
        self.add_user_button.clicked.connect(self.add_user)
        layout.addWidget(self.add_user_button)

        self.logout_button = QPushButton("Выход")
        self.logout_button.setFixedHeight(40) 
        self.logout_button.clicked.connect(self.logout)
        layout.addWidget(self.logout_button)

        self.setLayout(layout)
        self.load_users()

        self.resize(self.table.horizontalHeader().length() + 50, 600)

    def load_users(self):
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, login, password, role, is_blocked FROM users")
            users = cursor.fetchall()

            self.table.setRowCount(len(users))
            for row_idx, user in enumerate(users):
                user_id, login, password, role, is_blocked = user
                self.table.setItem(row_idx, 0, QTableWidgetItem(str(user_id)))
                self.table.setItem(row_idx, 1, QTableWidgetItem(login))
                self.table.setItem(row_idx, 2, QTableWidgetItem(password))
                self.table.setItem(row_idx, 3, QTableWidgetItem(role))
                self.table.setItem(row_idx, 4, QTableWidgetItem("Да" if is_blocked else "Нет"))

                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                unblock_button = QPushButton("Снять блокировку")
                unblock_button.setFixedSize(140, 30)
                unblock_button.clicked.connect(lambda _, uid=user_id: self.unblock_user(uid))
                actions_layout.addWidget(unblock_button)
                actions_layout.setContentsMargins(0, 0, 0, 0)  
                actions_widget.setLayout(actions_layout)

                self.table.setCellWidget(row_idx, 5, actions_widget) 

            self.table.resizeColumnsToContents() 
            self.table.resizeRowsToContents() 
            
            self.resize(self.table.horizontalHeader().length() + 50, self.height())

        finally:
            cursor.close()
            conn.close()

    def unblock_user(self, user_id):
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE users SET is_blocked = FALSE , failed_attempts = 0 WHERE id = %s", (user_id,))
            conn.commit()
            QMessageBox.information(self, "Успех", f"Пользователь с ID {user_id} разблокирован.")
            self.load_users()
        finally:
            cursor.close()
            conn.close()

    def add_user(self):
        self.add_user_form = AddUserForm(self) 
        self.add_user_form.show()

    def logout(self):
        self.close()  
        self.login_form = LoginForm()  
        self.login_form.show()

class AddUserForm(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent 
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Добавить пользователя")
        layout = QVBoxLayout()

        self.login_label = QLabel("Логин:")
        self.login_input = QLineEdit()
        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.role_label = QLabel("Роль:")
        self.role_input = QComboBox()
        self.role_input.addItems(["Администратор", "Пользователь"])

        self.add_button = QPushButton("Добавить")
        self.add_button.clicked.connect(self.handle_add_user)

        layout.addWidget(self.login_label)
        layout.addWidget(self.login_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.role_label)
        layout.addWidget(self.role_input)
        layout.addWidget(self.add_button)

        self.setLayout(layout)

    def handle_add_user(self):
        login = self.login_input.text()
        password = self.password_input.text()
        role = self.role_input.currentText()

        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Все поля обязательны для заполнения.")
            return

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id FROM users WHERE login = %s", (login,))
            if cursor.fetchone():
                QMessageBox.warning(self, "Ошибка", "Пользователь с таким логином уже существует.")
                return

            cursor.execute(
                "INSERT INTO users (login, password, role) VALUES (%s, %s, %s)",
                (login, password, role)
            )
            conn.commit()
            QMessageBox.information(self, "Успех", "Пользователь успешно добавлен.")
            self.parent.load_users()
            self.close()
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_form = LoginForm()
    login_form.show()
    
    sys.exit(app.exec_())
