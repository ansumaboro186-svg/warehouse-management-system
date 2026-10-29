import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
import hashlib
import hmac
import secrets


DB_PATH = Path(__file__).with_name("inventory.db")


class IMS:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1350x700+0+0")
        self.root.minsize(900, 550)
        self.root.title("Inventory Management System | Developed by Ansuma")
        self.root.config(bg="white")
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.show_login()

    def _build_main_ui(self):
        self.active_view = None
        for child in self.root.winfo_children():
            child.destroy()
        title = tk.Label(self.root, text="Inventory Management System", font=("Times New Roman", 32, "bold"),
                         bg="#2c3e50", fg="white", padx=20)
        title.place(x=0, y=0, relwidth=1, height=70)

        self.left_menu = tk.Frame(self.root, bd=2, relief=tk.RIDGE, bg="white")
        self.left_menu.place(x=0, y=70, width=250, relheight=1, height=-100)
        tk.Label(self.left_menu, text="Menu", font=("Times New Roman", 25, "bold"),
                 bg="#34495e", fg="white").pack(fill=tk.X)
        self._menu_button("Dashboard", self.show_dashboard)
        self._menu_button("Manage Products", lambda: self.show_manager("products"))
        self._menu_button("Manage Suppliers", lambda: self.show_manager("suppliers"))
        self._menu_button("Exit System", self.root.quit)

        self.content = tk.Frame(self.root, bg="white")
        self.content.place(x=260, y=85, relwidth=1, width=-275, relheight=1, height=-120)
        footer = tk.Label(self.root, text="IMS Dashboard | Developed by Ansuma", font=("Times New Roman", 15),
                          bg="#2c3e50", fg="white")
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        self.show_dashboard()

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                quantity INTEGER NOT NULL DEFAULT 0,
                price REAL NOT NULL DEFAULT 0,
                supplier TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS suppliers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                village TEXT NOT NULL DEFAULT '',
                pin TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                district TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS app_login (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)
        # Carry forward the original single administrator into the multi-admin table.
        legacy_admin = self.conn.execute("SELECT username, salt, password_hash FROM app_login WHERE id = 1").fetchone()
        if legacy_admin:
            self.conn.execute("INSERT OR IGNORE INTO app_users (username, salt, password_hash) VALUES (?, ?, ?)", legacy_admin)
        # Upgrade databases created by earlier versions without losing supplier data.
        supplier_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(suppliers)")}
        for column in ("phone", "village", "pin", "city", "district"):
            if column not in supplier_columns:
                self.conn.execute(f"ALTER TABLE suppliers ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        if "contact" in supplier_columns:
            self.conn.execute("UPDATE suppliers SET phone = contact WHERE phone = ''")
        if "address" in supplier_columns:
            self.conn.execute("UPDATE suppliers SET city = address WHERE city = ''")
        self.conn.commit()

    @staticmethod
    def _password_hash(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 310_000).hex()

    def show_login(self):
        self._show_auth_form(register=False)

    def _show_auth_form(self, register=False):
        for child in self.root.winfo_children():
            child.destroy()
        has_admins = self.conn.execute("SELECT 1 FROM app_users LIMIT 1").fetchone() is not None
        is_setup = not has_admins
        register = register or is_setup
        heading = "Create Admin Account" if register else "Admin Login"
        self.root.title(f"{heading} | Inventory Management System")
        panel = tk.Frame(self.root, bg="white", bd=2, relief=tk.RIDGE, padx=35, pady=28)
        panel.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        tk.Label(panel, text="Inventory Management System", font=("Times New Roman", 22, "bold"),
                 bg="white", fg="#2c3e50").pack(pady=(0, 6))
        tk.Label(panel, text=heading if register else "Please sign in to continue", font=("Arial", 14),
                 bg="white", fg="#555").pack(pady=(0, 18))
        tk.Label(panel, text="Name", font=("Arial", 11), bg="white", anchor="w").pack(fill=tk.X)
        name_entry = tk.Entry(panel, font=("Arial", 12), width=32)
        name_entry.pack(pady=(3, 12))
        tk.Label(panel, text="Password", font=("Arial", 11), bg="white", anchor="w").pack(fill=tk.X)
        password_entry = tk.Entry(panel, font=("Arial", 12), width=32, show="*")
        password_entry.pack(pady=(3, 12))
        confirm_entry = None
        if register:
            tk.Label(panel, text="Confirm password", font=("Arial", 11), bg="white", anchor="w").pack(fill=tk.X)
            confirm_entry = tk.Entry(panel, font=("Arial", 12), width=32, show="*")
            confirm_entry.pack(pady=(3, 12))

        def submit(_event=None):
            username = name_entry.get().strip()
            password = password_entry.get()
            if not username or not password:
                messagebox.showerror("Required fields", "Enter both your name and password.")
                return
            if register:
                if password != confirm_entry.get():
                    messagebox.showerror("Password mismatch", "The passwords do not match.")
                    return
                salt = secrets.token_hex(16)
                try:
                    self.conn.execute("INSERT INTO app_users (username, salt, password_hash) VALUES (?, ?, ?)",
                                      (username, salt, self._password_hash(password, salt)))
                except sqlite3.IntegrityError:
                    messagebox.showerror("Name already used", "An admin account with that name already exists.")
                    return
                self.conn.commit()
                self.root.title("Inventory Management System | Developed by Ansuma")
                self._build_main_ui()
                return
            saved = self.conn.execute("SELECT username, salt, password_hash FROM app_users WHERE username = ? COLLATE NOCASE",
                                      (username,)).fetchone()
            if not saved:
                messagebox.showerror("Login failed", "Name or password is incorrect.")
                password_entry.delete(0, tk.END)
                password_entry.focus_set()
                return
            supplied_hash = self._password_hash(password, saved[1])
            if hmac.compare_digest(supplied_hash, saved[2]):
                self.root.title("Inventory Management System | Developed by Ansuma")
                self._build_main_ui()
            else:
                messagebox.showerror("Login failed", "Name or password is incorrect.")
                password_entry.delete(0, tk.END)
                password_entry.focus_set()

        tk.Button(panel, text="Create account" if register else "Login", command=submit,
                  font=("Arial", 12, "bold"), bg="#2980b9", fg="white", padx=18, pady=7).pack(fill=tk.X, pady=(4, 0))
        if has_admins and not register:
            tk.Button(panel, text="Create new admin account", command=lambda: self._show_auth_form(register=True),
                      font=("Arial", 10), bg="white", fg="#2980b9", bd=0).pack(pady=(8, 0))
        elif has_admins and register:
            tk.Button(panel, text="Back to login", command=self.show_login,
                      font=("Arial", 10), bg="white", fg="#2980b9", bd=0).pack(pady=(8, 0))
        password_entry.bind("<Return>", submit)
        if confirm_entry:
            confirm_entry.bind("<Return>", submit)
        name_entry.focus_set()

    def _menu_button(self, text, command):
        tk.Button(self.left_menu, text=text, font=("Times New Roman", 17), bg="white", fg="black",
                  bd=0, anchor="w", padx=20, command=command).pack(fill=tk.X, pady=5)

    def _clear_content(self):
        for child in self.content.winfo_children():
            child.destroy()

    def show_dashboard(self):
        self.active_view = None
        self._clear_content()
        tk.Label(self.content, text="Dashboard", font=("Times New Roman", 27, "bold"), bg="white").pack(anchor="w", pady=(10, 20))
        cards = tk.Frame(self.content, bg="white")
        cards.pack(fill=tk.X)
        stats = [
            ("Total Products", "SELECT COUNT(*) FROM products", "#11b89a"),
            ("Total Suppliers", "SELECT COUNT(*) FROM suppliers", "#3498db"),
            ("Total Stock", "SELECT COALESCE(SUM(quantity), 0) FROM products", "#9b59b6"),
        ]
        for label, query, color in stats:
            value = self.conn.execute(query).fetchone()[0]
            card = tk.Label(cards, text=f"{label}\n{value}", bd=2, relief=tk.RIDGE,
                            font=("Times New Roman", 23, "bold"), bg=color, fg="white")
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, ipady=35)
        tk.Label(self.content, text="Use the menu to manage your inventory.", font=("Arial", 12), bg="white", fg="#555").pack(anchor="w", pady=25)

    def show_manager(self, kind):
        self.active_view = kind
        self._clear_content()
        is_products = kind == "products"
        title = "Manage Products" if is_products else "Manage Suppliers"
        fields = (["Product name", "Category", "Quantity", "Price", "Supplier"] if is_products
                  else ["Supplier name", "Phone (10 digits)", "Gmail address", "Village", "PIN", "City", "District"])
        columns = (["id", "name", "category", "quantity", "price", "supplier"] if is_products
                   else ["id", "name", "phone", "email", "village", "pin", "city", "district"])
        labels = (["ID", "Product", "Category", "Quantity", "Price", "Supplier"] if is_products
                  else ["ID", "Supplier", "Phone", "Gmail", "Village", "PIN", "City", "District"])
        table = "products" if is_products else "suppliers"
        field_columns = columns[1:]

        tk.Label(self.content, text=title, font=("Times New Roman", 25, "bold"), bg="white").pack(anchor="w", pady=(0, 12))
        form = tk.LabelFrame(self.content, text="Details", font=("Arial", 11, "bold"), bg="white", padx=10, pady=8)
        form.pack(fill=tk.X, pady=(0, 12))
        entries = {}
        supplier_names = [row[0] for row in self.conn.execute("SELECT name FROM suppliers ORDER BY name")]
        category_options = ["Electronics", "Clothing", "Food & Grocery", "Home & Kitchen", "Health & Beauty", "Office Supplies", "Other"]
        if is_products:
            for index, field in enumerate(fields):
                row, col = divmod(index, 3)
                key = field_columns[index]
                tk.Label(form, text=field, bg="white", anchor="w").grid(row=row * 2, column=col, sticky="w", padx=7, pady=(2, 0))
                if key == "category":
                    entry = ttk.Combobox(form, values=category_options, font=("Arial", 11), state="normal")
                elif key == "supplier":
                    entry = ttk.Combobox(form, values=supplier_names, font=("Arial", 11), state="readonly")
                else:
                    entry = tk.Entry(form, font=("Arial", 11))
                entry.grid(row=row * 2 + 1, column=col, sticky="ew", padx=7, pady=(0, 7))
                entries[key] = entry
        else:
            for index, (field, key) in enumerate(zip(fields[:3], field_columns[:3])):
                tk.Label(form, text=field, bg="white", anchor="w").grid(row=0, column=index, sticky="w", padx=7, pady=(2, 0))
                entry = tk.Entry(form, font=("Arial", 11))
                entry.grid(row=1, column=index, sticky="ew", padx=7, pady=(0, 7))
                entries[key] = entry
            address_form = tk.LabelFrame(form, text="Address", bg="white", padx=5, pady=4)
            address_form.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=(3, 4))
            for index, (field, key) in enumerate(zip(fields[3:], field_columns[3:])):
                tk.Label(address_form, text=field, bg="white", anchor="w").grid(row=0, column=index, sticky="w", padx=5, pady=(0, 2))
                entry = tk.Entry(address_form, font=("Arial", 11))
                entry.grid(row=1, column=index, sticky="ew", padx=5, pady=(0, 4))
                entries[key] = entry
                address_form.grid_columnconfigure(index, weight=1)
        for col in range(3):
            form.grid_columnconfigure(col, weight=1)

        tree_frame = tk.Frame(self.content)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        for col, label in zip(columns, labels):
            tree.heading(col, text=label)
            tree.column(col, width=90 if col == "id" else 150, anchor="center" if col in ("id", "quantity", "price") else "w")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        def refresh():
            tree.delete(*tree.get_children())
            for record in self.conn.execute(f"SELECT {', '.join(columns)} FROM {table} ORDER BY id DESC"):
                tree.insert("", tk.END, values=record)

        def selected_id():
            selection = tree.selection()
            if not selection:
                messagebox.showinfo("Select a record", "Choose a row from the table first.")
                return None
            return tree.item(selection[0], "values")[0]

        def clear_form():
            for entry in entries.values():
                entry.delete(0, tk.END)
            tree.selection_remove(tree.selection())

        def add_record():
            values = [entries[col].get().strip() for col in field_columns]
            if not values[0]:
                messagebox.showerror("Missing information", f"{fields[0]} is required.")
                return
            if not is_products and (not values[1].isdigit() or len(values[1]) != 10):
                messagebox.showerror("Invalid phone number", "Enter a phone number with exactly 10 digits.")
                return
            if not is_products and not values[2].lower().endswith("@gmail.com"):
                messagebox.showerror("Invalid Gmail address", "Enter an email address ending in @gmail.com.")
                return
            if not is_products and (not values[4].isdigit() or len(values[4]) != 6):
                messagebox.showerror("Invalid PIN", "Enter a PIN with exactly 6 digits.")
                return
            try:
                if is_products:
                    quantity = int(values[2] or 0)
                    price = float(values[3] or 0)
                    if quantity < 0 or price < 0:
                        raise ValueError
                    values[2], values[3] = quantity, price
                self.conn.execute(f"INSERT INTO {table} ({', '.join(field_columns)}) VALUES ({', '.join('?' for _ in values)})", values)
                self.conn.commit()
                clear_form(); refresh()
            except ValueError:
                messagebox.showerror("Invalid number", "Quantity and price must be valid non-negative numbers.")
            except sqlite3.Error as exc:
                messagebox.showerror("Database error", str(exc))

        def load_selected(_event=None):
            selection = tree.selection()
            if not selection:
                return
            values = tree.item(selection[0], "values")
            for col, value in zip(field_columns, values[1:]):
                entries[col].delete(0, tk.END)
                entries[col].insert(0, value)

        def update_record():
            record_id = selected_id()
            if record_id is None:
                return
            values = [entries[col].get().strip() for col in field_columns]
            if not values[0]:
                messagebox.showerror("Missing information", f"{fields[0]} is required.")
                return
            if not is_products and (not values[1].isdigit() or len(values[1]) != 10):
                messagebox.showerror("Invalid phone number", "Enter a phone number with exactly 10 digits.")
                return
            if not is_products and not values[2].lower().endswith("@gmail.com"):
                messagebox.showerror("Invalid Gmail address", "Enter an email address ending in @gmail.com.")
                return
            if not is_products and (not values[4].isdigit() or len(values[4]) != 6):
                messagebox.showerror("Invalid PIN", "Enter a PIN with exactly 6 digits.")
                return
            try:
                if is_products:
                    quantity = int(values[2] or 0)
                    price = float(values[3] or 0)
                    if quantity < 0 or price < 0:
                        raise ValueError
                    values[2], values[3] = quantity, price
                assignments = ", ".join(f"{col} = ?" for col in field_columns)
                self.conn.execute(f"UPDATE {table} SET {assignments} WHERE id = ?", (*values, record_id))
                self.conn.commit()
                clear_form(); refresh()
            except ValueError:
                messagebox.showerror("Invalid number", "Quantity and price must be valid non-negative numbers.")
            except sqlite3.Error as exc:
                messagebox.showerror("Database error", str(exc))

        def delete_record():
            record_id = selected_id()
            if record_id is None:
                return
            if messagebox.askyesno("Delete record", "Delete the selected record permanently?"):
                self.conn.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))
                self.conn.commit()
                clear_form(); refresh()

        buttons = tk.Frame(self.content, bg="white")
        buttons.pack(fill=tk.X, pady=10)
        for text, command, color in [("Add", add_record, "#27ae60"), ("Update selected", update_record, "#2980b9"),
                                     ("Delete selected", delete_record, "#c0392b"), ("Clear", clear_form, "#7f8c8d")]:
            tk.Button(buttons, text=text, command=command, bg=color, fg="white", padx=12, pady=6).pack(side=tk.LEFT, padx=(0, 8))
        tree.bind("<<TreeviewSelect>>", load_selected)
        refresh()

    def close(self):
        self.conn.close()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = IMS(root)
    root.mainloop()
