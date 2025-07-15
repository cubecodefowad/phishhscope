import pyautogui
import random
import string
import time
import pygetwindow as gw

def random_char():
    chars = string.ascii_lowercase + string.digits
    return random.choice(chars)

def is_vscode_active():
    # Get the currently active window title
    active_window = gw.getActiveWindow()
    if active_window is None:
        return False
    title = active_window.title.lower()
    # Check if 'visual studio code' or 'vscode' is in the window title
    return 'visual studio code' in title or 'vscode' in title

try:
    print("Script started. It will only type when VSCode is active.")
    while True:
        if is_vscode_active():
            char = random_char()
            pyautogui.typewrite(char)
            print(f"Typed '{char}'")
            time.sleep(1)
        else:
            # Wait and check again in 1 second
            print("VSCode not active, waiting...")
            time.sleep(1)

except KeyboardInterrupt:
    print("\nStopped typing.")
