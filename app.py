#!/usr/bin/env python3
"""
Yahoo-Discord Bridge - All-in-One Application

This is the main application that:
1. Automatically configures Yahoo Messenger registry settings
2. Downloads/installs Yahoo Messenger if needed
3. Provides simple GUI - just enter token and click Start
4. Runs the bridge in the background

The user should NEVER need to touch command line or registry.
"""

import asyncio
import ctypes
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import tempfile
import shutil

# Only import winreg on Windows
if platform.system() == 'Windows':
    import winreg

# Configure logging to file with UTF-8 encoding to handle Discord unicode/emoji
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bridge.log')

# Custom stream handler that handles encoding errors gracefully
class SafeStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            # Replace unencodable characters instead of crashing
            stream = self.stream
            try:
                stream.write(msg + self.terminator)
            except UnicodeEncodeError:
                # Fall back to ASCII with replacement
                stream.write(msg.encode('ascii', 'replace').decode('ascii') + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        SafeStreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# App directory
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, 'config.json')
YM_INSTALLER_URL = "https://archive.org/download/yahoo-messenger-11.5.0.228/ymsgr1150_0228_us.exe"
YM_INSTALLER_BACKUP = "https://web.archive.org/web/2012/http://download.yahoo.com/dl/msgr/ymsgr1150_0228_us.exe"


class TextHandler(logging.Handler):
    """Custom logging handler that writes to a Tkinter Text widget"""

    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.see(tk.END)  # Auto-scroll to bottom
            self.text_widget.configure(state='disabled')
            # Limit to 500 lines to prevent memory issues
            lines = int(self.text_widget.index('end-1c').split('.')[0])
            if lines > 500:
                self.text_widget.configure(state='normal')
                self.text_widget.delete('1.0', '100.0')
                self.text_widget.configure(state='disabled')
        # Schedule on main thread
        try:
            self.text_widget.after(0, append)
        except:
            pass  # Widget may be destroyed


class YahooDiscordBridgeApp:
    """Main application window"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Yahoo-Discord Bridge")
        self.root.geometry("550x600")
        self.root.resizable(True, True)

        # Center window
        self.center_window()

        # State
        self.bridge = None
        self.bridge_thread = None
        self.running = False
        self.config = self.load_config()
        self.http_server = None  # Yahoo HTTP/HTTPS server for YM9

        # Build UI
        self.create_ui()

        # Auto-check setup on start
        self.root.after(500, self.check_setup)

    def center_window(self):
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'+{x}+{y}')

    def load_config(self):
        """Load saved configuration"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'discord_token': '', 'auto_start': False}

    def save_config(self):
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def create_ui(self):
        """Create the user interface"""
        # Main container
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill='both', expand=True)

        # Header
        header = ttk.Label(main, text="Yahoo-Discord Bridge",
                          font=('Segoe UI', 18, 'bold'))
        header.pack(pady=(0, 5))

        subtitle = ttk.Label(main, text="Use Yahoo Messenger with your Discord friends!",
                            font=('Segoe UI', 10))
        subtitle.pack(pady=(0, 20))

        # Setup Status Frame
        status_frame = ttk.LabelFrame(main, text="Setup Status", padding=10)
        status_frame.pack(fill='x', pady=(0, 15))

        # YM Status
        ym_row = ttk.Frame(status_frame)
        ym_row.pack(fill='x', pady=2)
        ttk.Label(ym_row, text="Yahoo Messenger:").pack(side='left')
        self.ym_status = ttk.Label(ym_row, text="Checking...", foreground='gray')
        self.ym_status.pack(side='left', padx=(10, 0))
        self.ym_btn = ttk.Button(ym_row, text="Install", command=self.install_ym, width=10)
        self.ym_btn.pack(side='right')
        self.ym_btn.pack_forget()  # Hide until needed

        # Registry Status
        reg_row = ttk.Frame(status_frame)
        reg_row.pack(fill='x', pady=2)
        ttk.Label(reg_row, text="Registry Config:").pack(side='left')
        self.reg_status = ttk.Label(reg_row, text="Checking...", foreground='gray')
        self.reg_status.pack(side='left', padx=(10, 0))
        self.reg_btn = ttk.Button(reg_row, text="Configure", command=self.configure_registry, width=10)
        self.reg_btn.pack(side='right')
        self.reg_btn.pack_forget()  # Hide until needed

        # Discord Account Frame
        discord_frame = ttk.LabelFrame(main, text="Discord Account", padding=10)
        discord_frame.pack(fill='x', pady=(0, 15))

        # Token entry
        ttk.Label(discord_frame, text="Discord Token:").pack(anchor='w')

        token_row = ttk.Frame(discord_frame)
        token_row.pack(fill='x', pady=(2, 5))

        self.token_var = tk.StringVar(value=self.config.get('discord_token', ''))
        self.token_entry = ttk.Entry(token_row, textvariable=self.token_var,
                                     show='*', font=('Consolas', 9))
        self.token_entry.pack(side='left', fill='x', expand=True)

        self.show_token_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(token_row, text="Show", variable=self.show_token_var,
                       command=self.toggle_token).pack(side='left', padx=(5, 0))

        # Status
        self.discord_status = ttk.Label(discord_frame, text="", foreground='gray')
        self.discord_status.pack(anchor='w')

        if self.token_var.get():
            self.discord_status.config(text="Token saved", foreground='green')

        # Connection Status
        conn_frame = ttk.Frame(main)
        conn_frame.pack(fill='x', pady=(0, 15))

        ttk.Label(conn_frame, text="Bridge Status:", font=('Segoe UI', 10)).pack(side='left')
        self.conn_status = ttk.Label(conn_frame, text="Not Running",
                                     font=('Segoe UI', 10, 'bold'), foreground='gray')
        self.conn_status.pack(side='left', padx=(10, 0))

        # Big Start/Stop Button
        self.start_btn = ttk.Button(main, text="▶ Start Bridge",
                                    command=self.toggle_bridge,
                                    style='Big.TButton')
        self.start_btn.pack(pady=10, ipadx=20, ipady=10)

        # Style for big button
        style = ttk.Style()
        style.configure('Big.TButton', font=('Segoe UI', 12, 'bold'))

        # Instructions
        instructions = ttk.Label(main, text="After starting, open Yahoo Messenger and sign in.\n"
                                           "Your Discord friends will appear in your buddy list!",
                                font=('Segoe UI', 9), foreground='gray', justify='center')
        instructions.pack(pady=(15, 10))

        # Log Console
        log_frame = ttk.LabelFrame(main, text="Log Console", padding=5)
        log_frame.pack(fill='both', expand=True, pady=(5, 0))

        # Text widget with scrollbar
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.pack(side='right', fill='y')

        self.log_text = tk.Text(log_frame, height=10, width=60,
                                font=('Consolas', 9), wrap='word',
                                bg='#1e1e1e', fg='#00ff00',
                                state='disabled',
                                yscrollcommand=log_scroll.set)
        self.log_text.pack(fill='both', expand=True)
        log_scroll.config(command=self.log_text.yview)

        # Add log handler
        self.setup_log_handler()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def toggle_token(self):
        """Toggle token visibility"""
        self.token_entry.config(show='' if self.show_token_var.get() else '*')

    def setup_log_handler(self):
        """Set up logging to the text widget"""
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                     datefmt='%H:%M:%S'))
        text_handler.setLevel(logging.DEBUG)

        # Add handler to root logger so all modules log here
        root_logger = logging.getLogger()
        root_logger.addHandler(text_handler)
        root_logger.setLevel(logging.DEBUG)

        # Initial log message
        logger.info("Yahoo-Discord Bridge ready")

    def show_token_help(self):
        """Show help for getting Discord token"""
        help_window = tk.Toplevel(self.root)
        help_window.title("How to Get Your Discord Token")
        help_window.geometry("450x350")
        help_window.resizable(False, False)
        help_window.transient(self.root)
        help_window.grab_set()

        frame = ttk.Frame(help_window, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="How to Get Your Discord Token",
                 font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        steps = """1. Open Discord in your web browser
   (Go to discord.com/app and log in)

2. Press F12 to open Developer Tools

3. Click the "Network" tab at the top

4. In the filter box, type: api

5. Click on any request in the list

6. Look in "Request Headers" section

7. Find "authorization" and copy the value
   (It's a long string of letters and numbers)

⚠️ NEVER share your token with anyone!
   It gives full access to your account."""

        text = tk.Text(frame, wrap='word', font=('Segoe UI', 10),
                      height=14, width=45)
        text.insert('1.0', steps)
        text.config(state='disabled')
        text.pack(fill='both', expand=True)

        ttk.Button(frame, text="Got it!",
                  command=help_window.destroy).pack(pady=(15, 0))

    def discord_signin(self):
        """Open Discord in browser and show instructions for getting token"""
        import webbrowser

        # Open Discord in default browser
        webbrowser.open("https://discord.com/app")

        # Show instructions
        help_window = tk.Toplevel(self.root)
        help_window.title("Get Your Discord Token")
        help_window.geometry("500x400")
        help_window.resizable(False, False)
        help_window.transient(self.root)
        help_window.grab_set()

        frame = ttk.Frame(help_window, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Get Your Discord Token",
                 font=('Segoe UI', 14, 'bold')).pack(pady=(0, 15))

        steps = """Discord just opened in your browser.

Once logged in, press F12 to open Developer Tools, then:

1. Click the "Console" tab

2. Paste this code and press Enter:

   (webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken).exports.default.getToken()

3. Copy the token that appears (without quotes)

4. Paste it below and click Save:"""

        ttk.Label(frame, text=steps, justify='left',
                 font=('Segoe UI', 10)).pack(anchor='w', fill='x')

        # Token entry
        token_frame = ttk.Frame(frame)
        token_frame.pack(fill='x', pady=(15, 10))

        token_var = tk.StringVar()
        token_entry = ttk.Entry(token_frame, textvariable=token_var,
                               font=('Consolas', 10), width=50)
        token_entry.pack(side='left', fill='x', expand=True)

        def save_token():
            token = token_var.get().strip().strip('"').strip("'")
            if token and len(token) > 50:
                self.token_var.set(token)
                self.config['discord_token'] = token
                self.save_config()
                self.discord_status.config(text="Signed in!", foreground='green')
                help_window.destroy()
                messagebox.showinfo("Success", "Token saved! Click 'Start Bridge' to begin.")
            else:
                messagebox.showerror("Invalid Token", "That doesn't look like a valid token.\nMake sure you copied the whole thing.")

        ttk.Button(token_frame, text="Save", command=save_token,
                  width=8).pack(side='left', padx=(10, 0))

        ttk.Button(frame, text="Cancel",
                  command=help_window.destroy).pack(pady=(10, 0))

    def check_setup(self):
        """Check if everything is set up correctly"""
        if platform.system() != 'Windows':
            self.ym_status.config(text="Windows required", foreground='red')
            self.reg_status.config(text="Windows required", foreground='red')
            return

        # Check Yahoo Messenger installation
        ym_installed = self.check_ym_installed()
        if ym_installed:
            self.ym_status.config(text="✓ Installed", foreground='green')
            self.ym_btn.pack_forget()
        else:
            self.ym_status.config(text="✗ Not installed", foreground='red')
            self.ym_btn.pack(side='right')

        # Check registry configuration
        reg_configured = self.check_registry()
        if reg_configured:
            self.reg_status.config(text="✓ Configured", foreground='green')
            self.reg_btn.pack_forget()
        else:
            self.reg_status.config(text="✗ Not configured", foreground='orange')
            self.reg_btn.pack(side='right')

    def check_ym_installed(self):
        """Check if Yahoo Messenger is installed"""
        if platform.system() != 'Windows':
            return False

        # Check common installation paths
        paths = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Yahoo!\Messenger\YahooMessenger.exe"),
            os.path.expandvars(r"%ProgramFiles%\Yahoo!\Messenger\YahooMessenger.exe"),
            os.path.join(APP_DIR, "YahooMessenger", "YahooMessenger.exe"),
        ]

        for path in paths:
            if os.path.exists(path):
                return True

        # Check registry for install path
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Yahoo\Pager") as key:
                return True
        except:
            pass

        return False

    def check_registry(self):
        """Check if registry is configured for localhost"""
        if platform.system() != 'Windows':
            return False

        # Try both YM9 and YM11 registry paths
        reg_paths = [
            r"Software\Yahoo\Pager",
            r"Software\Yahoo\pager",
            r"Software\Yahoo\Messenger",
        ]

        for path in reg_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    server, _ = winreg.QueryValueEx(key, "socket server")
                    if server == "127.0.0.1":
                        logger.info(f"Registry configured at {path}")
                        return True
            except:
                continue
        return False

    def configure_registry(self):
        """Configure Yahoo Messenger to connect to localhost"""
        if platform.system() != 'Windows':
            messagebox.showerror("Error", "This feature requires Windows")
            return

        try:
            # Configure all possible Yahoo Messenger registry paths
            reg_paths = [
                r"Software\Yahoo\Pager",
                r"Software\Yahoo\pager",
            ]

            configured = 0
            for path in reg_paths:
                try:
                    # Open or create the registry key
                    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path,
                                             0, winreg.KEY_SET_VALUE)

                    # Set socket server to localhost
                    winreg.SetValueEx(key, "socket server", 0, winreg.REG_SZ, "127.0.0.1")

                    # Update IPLookup to include localhost first
                    winreg.SetValueEx(key, "IPLookup", 0, winreg.REG_SZ,
                                    "127.0.0.1,scs.msg.yahoo.com")

                    winreg.CloseKey(key)
                    logger.info(f"Configured registry: {path}")
                    configured += 1
                except Exception as e:
                    logger.warning(f"Could not configure {path}: {e}")

            if configured > 0:
                messagebox.showinfo("Success", "Registry configured successfully!\n\n"
                                  "Yahoo Messenger will now connect through the bridge.")
            else:
                messagebox.showwarning("Warning", "Could not configure registry.\n"
                                      "You may need to run as Administrator.")
            self.check_setup()

        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Try running as Administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to configure registry:\n{e}")

    def install_ym(self):
        """Download and install Yahoo Messenger"""
        if messagebox.askyesno("Install Yahoo Messenger",
                              "This will download Yahoo Messenger 11.\n\n"
                              "Continue?"):
            # Run in background thread
            self.ym_status.config(text="Downloading...", foreground='blue')
            self.ym_btn.config(state='disabled')
            threading.Thread(target=self._download_ym, daemon=True).start()

    def _download_ym(self):
        """Download YM installer in background"""
        try:
            # Create temp file
            temp_dir = tempfile.mkdtemp()
            installer_path = os.path.join(temp_dir, "ymsgr_setup.exe")

            # Try primary URL
            try:
                urllib.request.urlretrieve(YM_INSTALLER_URL, installer_path,
                                          reporthook=self._download_progress)
            except:
                # Try backup URL
                urllib.request.urlretrieve(YM_INSTALLER_BACKUP, installer_path,
                                          reporthook=self._download_progress)

            # Run installer
            self.root.after(0, lambda: self.ym_status.config(text="Installing...", foreground='blue'))
            subprocess.run([installer_path], check=True)

            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

            # Refresh status
            self.root.after(0, self.check_setup)
            self.root.after(0, lambda: messagebox.showinfo("Success",
                           "Yahoo Messenger installed!\n\nRegistry will be configured automatically."))
            self.root.after(100, self.configure_registry)

        except Exception as e:
            logger.error(f"Failed to install YM: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error",
                           f"Failed to install Yahoo Messenger:\n{e}"))
            self.root.after(0, self.check_setup)
        finally:
            self.root.after(0, lambda: self.ym_btn.config(state='normal'))

    def _download_progress(self, block_num, block_size, total_size):
        """Update download progress"""
        if total_size > 0:
            percent = int(block_num * block_size * 100 / total_size)
            self.root.after(0, lambda p=percent: self.ym_status.config(
                text=f"Downloading... {min(p, 100)}%"))

    def toggle_bridge(self):
        """Start or stop the bridge"""
        if self.running:
            self.stop_bridge()
        else:
            self.start_bridge()

    def start_bridge(self):
        """Start the bridge"""
        token = self.token_var.get().strip()

        if not token:
            messagebox.showerror("Error", "Please enter your Discord token first!")
            return

        # Save token
        self.config['discord_token'] = token
        self.save_config()

        # Update UI
        self.running = True
        self.start_btn.config(text="■ Stop Bridge")
        self.conn_status.config(text="Starting...", foreground='orange')
        self.token_entry.config(state='disabled')

        # Start bridge in background
        self.bridge_thread = threading.Thread(target=self._run_bridge, daemon=True)
        self.bridge_thread.start()

    def _run_bridge(self):
        """Run the bridge (background thread)"""
        try:
            logger.info("Starting bridge...")

            # Import bridge modules - use threaded YMSG server for Wine compatibility
            from ymsg.server_threaded import YMSGServerThreaded
            from discord_client.client import DiscordBridge
            from yahoo_http_server import YahooHTTPServer

            logger.info("Modules imported successfully")

            # Start HTTP/HTTPS server for YM9+ authentication
            logger.info("Starting Yahoo HTTP/HTTPS server for YM9 auth...")
            self.http_server = YahooHTTPServer(http_port=80, https_port=443)
            self.http_server.start()

            # Create YMSG server (threaded, starts immediately)
            logger.info("Creating YMSG server on 127.0.0.1:5050...")
            ymsg_server = YMSGServerThreaded(host='127.0.0.1', port=5050)
            ymsg_server.start()
            logger.info("YMSG server started - waiting for Yahoo Messenger connections")
            self.root.after(0, lambda: self.conn_status.config(
                text="YMSG Ready - Connecting Discord...", foreground='orange'))

            # Store reference for message forwarding
            self.ymsg_server = ymsg_server

            # Create event loop for Discord
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            logger.info("Creating Discord client...")
            discord_client = DiscordBridge()

            async def run():
                # Connect Discord
                logger.info("Connecting to Discord...")

                # Set up Discord callbacks for messages
                async def on_friend_message(sender, content):
                    logger.info(f"Discord DM from {sender}: {content}")
                    # Forward to YM client (threaded server, synchronous call)
                    for session in ymsg_server.sessions.values():
                        if session.authenticated:
                            ymsg_server.send_message_to_client(sender, session.username, content)

                discord_client.on_friend_message = on_friend_message

                # Task to wait for Discord to be ready and then load friends
                async def wait_and_load_friends():
                    logger.info("Waiting for Discord to be ready...")
                    try:
                        await discord_client.wait_until_ready()
                        logger.info("Discord is ready!")
                        logger.info(f"Logged in as {discord_client.user.name} ({discord_client.user.id})")

                        # Get friends and update YMSG server
                        friends = discord_client.get_friends_for_ymsg()
                        statuses = discord_client.get_friend_statuses()
                        ymsg_server.update_friends(friends, statuses)
                        logger.info(f"Loaded {sum(len(v) for v in friends.values())} friends")

                        self.root.after(0, lambda: self.conn_status.config(
                            text="Connected!", foreground='green'))
                    except Exception as e:
                        logger.error(f"Error waiting for Discord: {e}")
                        import traceback
                        logger.error(traceback.format_exc())

                # Start the wait task before connecting
                loop.create_task(wait_and_load_friends())

                # Connect Discord (this blocks)
                try:
                    await discord_client.start(self.config['discord_token'])
                except Exception as discord_err:
                    logger.error(f"Discord connection failed: {discord_err}")
                    raise

            loop.run_until_complete(run())

        except Exception as e:
            import traceback
            error_msg = traceback.format_exc()
            logger.error(f"Bridge error: {error_msg}")
            self.root.after(0, lambda: messagebox.showerror("Error",
                           f"Bridge error:\n{e}"))
            self.root.after(0, self.stop_bridge)

    def stop_bridge(self):
        """Stop the bridge"""
        self.running = False
        self.start_btn.config(text="▶ Start Bridge")
        self.conn_status.config(text="Stopped", foreground='gray')
        self.token_entry.config(state='normal')

        # Stop HTTP/HTTPS server
        if self.http_server:
            try:
                self.http_server.stop()
            except:
                pass
            self.http_server = None

    def on_close(self):
        """Handle window close"""
        if self.running:
            if messagebox.askyesno("Exit", "Bridge is running. Stop and exit?"):
                self.stop_bridge()
                self.root.after(500, self.root.destroy)
        else:
            self.root.destroy()

    def run(self):
        """Start the application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    app = YahooDiscordBridgeApp()
    app.run()


if __name__ == '__main__':
    main()
