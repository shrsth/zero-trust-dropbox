# client_gui.py (No significant changes needed)
import tkinter as tk, os
from tkinter import messagebox, font, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from client import authenticate, list_files, upload_file as client_upload, download_file as client_download

ACCESS_TOKEN, USER_PASSWORD, TIMER_SECONDS = None, None, 0

class App(ttk.Window):
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("Zero-Trust Dropbox Client"), self.geometry("750x600")
        self.title_font = font.Font(family="Segoe UI", size=20, weight="bold")
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1), container.grid_columnconfigure(0, weight=1)
        self.frames = {F: F(container, self) for F in (LoginFrame, MainFrame)}
        for frame in self.frames.values(): frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(LoginFrame)
    def show_frame(self, page_class): self.frames[page_class].tkraise()
    def start_session(self, token_info, password):
        global ACCESS_TOKEN, TIMER_SECONDS, USER_PASSWORD
        ACCESS_TOKEN, TIMER_SECONDS, USER_PASSWORD = token_info["access_token"], token_info["expires_in"], password
        self.show_frame(MainFrame), self.frames[MainFrame].start_session_tasks()
    def end_session(self):
        global ACCESS_TOKEN, USER_PASSWORD
        ACCESS_TOKEN, USER_PASSWORD = None, None
        messagebox.showwarning("Session Expired", "Please log in again.")
        self.show_frame(LoginFrame), self.frames[LoginFrame].clear_fields()

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.columnconfigure(0, weight=1), self.rowconfigure(0, weight=1)
        form_frame = ttk.Frame(self)
        form_frame.grid(row=0, column=0)
        ttk.Label(form_frame, text="Secure Client Login", font=controller.title_font).grid(row=0, column=0, columnspan=2, pady=(0, 30))
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.username_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 10))
        self.username_entry.grid(row=1, column=1, padx=10, pady=10), self.username_entry.insert(0, "G7")
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.password_entry = ttk.Entry(form_frame, show="*", width=30, font=("Segoe UI", 10))
        self.password_entry.grid(row=2, column=1, padx=10, pady=10)
        ttk.Label(form_frame, text="MFA Code:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.mfa_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 10))
        self.mfa_entry.grid(row=3, column=1, padx=10, pady=10)
        ttk.Button(form_frame, text="Login", command=self.handle_login, bootstyle=SUCCESS).grid(row=4, column=0, columnspan=2, pady=(20, 0), sticky="ew", ipady=5)

    def handle_login(self):
        username, password, mfa_code = self.username_entry.get(), self.password_entry.get(), self.mfa_entry.get()
        if not all([username, password, mfa_code]):
            messagebox.showerror("Login Failed", "All fields are required.")
            return
        response = authenticate(username, password, mfa_code) # This function now does all the work
        if response and "access_token" in response:
            self.controller.start_session(response, password)
        else:
            error = response.get("error", "An unknown error occurred") if response else "Could not connect"
            messagebox.showerror("Login Failed", error.capitalize())
    def clear_fields(self): self.password_entry.delete(0, tk.END), self.mfa_entry.delete(0, tk.END)

class MainFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding="15 15 15 15")
        self.controller = controller
        self.columnconfigure(0, weight=1), self.rowconfigure(2, weight=1)
        header_frame = ttk.Frame(self)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.timer_label = ttk.Label(header_frame, text="Session Timer: --:--", font=("Segoe UI", 11, "bold"))
        self.timer_label.pack(side="right")
        ttk.Label(header_frame, text="Zero-Trust File Vault", font=controller.title_font).pack(side="left")
        button_frame = ttk.Frame(self)
        button_frame.grid(row=1, column=0, pady=(0, 10), sticky="w")
        ttk.Button(button_frame, text="Upload Encrypted File", command=self.upload_action, bootstyle=SUCCESS).pack(side="left", padx=(0, 10))
        ttk.Button(button_frame, text="Download & Decrypt File", command=self.download_action, bootstyle=INFO).pack(side="left", padx=(0, 10))
        ttk.Button(button_frame, text="Refresh List", command=self.populate_file_list).pack(side="left")
        list_frame = ttk.Frame(self)
        list_frame.grid(row=2, column=0, sticky="nsew")
        list_frame.rowconfigure(0, weight=1), list_frame.columnconfigure(0, weight=1)
        self.file_list = tk.Listbox(list_frame, height=10, font=("Segoe UI", 10))
        self.file_list.grid(row=0, column=0, sticky="nsew")
        log_frame = ttk.Labelframe(self, text="Activity Logs", padding=10)
        log_frame.grid(row=3, column=0, pady=(10, 0), sticky="ew")
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=6, font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky="ew")
    def start_session_tasks(self): self.populate_file_list(), self.update_timer()
    def log_message(self, message): self.log_text.insert("1.0", message + "\n")
    def populate_file_list(self):
        if not ACCESS_TOKEN: return
        self.file_list.delete(0, tk.END)
        files = list_files(ACCESS_TOKEN)
        for f in files: self.file_list.insert(tk.END, f)
        if not files: self.file_list.insert(tk.END, "(No files on server)")
    def update_timer(self):
        global TIMER_SECONDS
        if TIMER_SECONDS > 0:
            mins, secs = divmod(TIMER_SECONDS, 60)
            self.timer_label.config(text=f"Session Expires in: {mins:02d}:{secs:02d}", foreground="#0078D4")
            TIMER_SECONDS -= 1
            self.after(1000, self.update_timer)
        else:
            self.timer_label.config(text="Session Expired", foreground="red")
            self.controller.end_session()
    def upload_action(self):
        if not all([ACCESS_TOKEN, USER_PASSWORD]): return
        file_path = filedialog.askopenfilename()
        if file_path:
            filename = os.path.basename(file_path)
            self.log_message(f"Encrypting and uploading {filename}...")
            success = client_upload(ACCESS_TOKEN, file_path, USER_PASSWORD)
            self.log_message(f"✅ Upload successful: {filename}" if success else f"❌ Upload failed for {filename}")
            if success: self.populate_file_list()
    def download_action(self):
        if not all([ACCESS_TOKEN, USER_PASSWORD]): return
        selected = self.file_list.curselection()
        if selected:
            file_name = self.file_list.get(selected[0])
            save_path = filedialog.asksaveasfilename(initialfile=file_name)
            if save_path:
                self.log_message(f"Downloading and decrypting {file_name}...")
                success, error = client_download(ACCESS_TOKEN, file_name, save_path, USER_PASSWORD)
                self.log_message(f"✅ Decryption successful!" if success else f"❌ Download Failed: {error}")
        else: messagebox.showwarning("Warning", "Please select a file to download.")

if __name__ == "__main__":
    app = App()
    app.mainloop()