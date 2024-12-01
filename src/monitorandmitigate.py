import os
from dotenv import load_dotenv
import time
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32file
import win32con
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import requests

# Load environment variables from a .env file
load_dotenv()

# Ensure the folder_path is a valid string by retrieving it from the environment variables
folder_path = os.getenv("FOLDER_PATH")
to_email = os.getenv("TO_EMAIL")
email_url = os.getenv("EMAIL_URL")
api_key = os.getenv("MAIL_GUN_API_KEY")
from_user = os.getenv("FROM_EMAIL")

email_sent = False


# Locking function: This function is used to lock a file to prevent further modification.
# It opens the file for reading and writing, and locks it using the win32file library.
# Locking is done at the file level, meaning no other process or thread can modify the file while locked.
# The file handle is returned to allow unlocking later. If the locking fails, the function returns None.
def lock_file(file_path):
    try:
        # Open the file for reading and writing
        file_handle = win32file.CreateFile(
            file_path,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0,  # No sharing
            None,  # Default security
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None
        )

        # Attempt to lock the file
        win32file.LockFile(file_handle, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
        print(f"Locked file: {file_path}")
        return file_handle
    except Exception as e:
        print(f"Failed to lock file {file_path}: {e}")
        return None


# Unlocking function: This function releases the lock on a file using its file handle.
# Once unlocked, other processes or threads can access the file for modification.
# If the unlocking fails, an error message is printed.
def unlock_file(file_handle):
    try:
        # Unlock the file
        win32file.UnlockFile(file_handle, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
        print("Released lock on file.")
        win32file.CloseHandle(file_handle)
    except Exception as e:
        print(f"Failed to release lock: {e}")


# Send email about suspicious activity to the Admin
def send_email_to_admin():
    try:
        response = requests.post(
            email_url,
            auth=("api", api_key),
            data={
                "from": from_user,
                "to": [to_email],
                "subject": "Suspicious Activity Detected",
                "text": (
                    "A suspicious activity has been detected in your system where a ransomware might "
                    "be modifying your folder. Please take necessary actions in time."
                )
            }
        )
        # Check if the request was successful
        if response.status_code == 200:
            print("Email sent successfully!")
        else:
            print(f"Failed to send email. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"An error occurred while sending the email: {e}")


# Lock files in a folder: This function locks all files within a specified folder.
# It walks through the folder recursively, locks each file it finds, and returns a list of file handles.
# The file handles can later be used to unlock the files after suspicious activity has been detected.
def lock_files_in_folder(folder_path):
    if not folder_path:
        print("Error: The folder path is not valid or is None.")
        return []

    # Get all files in the folder and lock them
    file_handles = []
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_handle = lock_file(file_path)
            if file_handle:
                file_handles.append(file_handle)

    return file_handles


# Generate a PDF report: This function generates a report of the modified files.
# It accepts a list of modified files (with timestamps), creates a PDF, and writes the details to it.
# If there are more files than can fit on one page, it creates additional pages.
# The PDF is saved with the name "modified_files_report.pdf".
def generate_pdf_report(modified_files):
    # Set the file name for the PDF
    pdf_filename = "modified_files_report.pdf"

    # Create a canvas to write to a PDF
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter  # Default letter page size in points (72 points = 1 inch)

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 50, "Suspicious Activity Report")

    # Subtitle
    c.setFont("Helvetica", 12)
    c.drawString(100, height - 70, "Files modified before being locked:")

    # Table header
    c.setFont("Helvetica-Bold", 10)
    c.drawString(100, height - 100, "File Name")
    c.drawString(400, height - 100, "Modification Time")

    # Set the font for table content
    c.setFont("Helvetica", 10)

    # Starting Y position for table rows
    y_position = height - 120
    max_y_position = 60  # Set the lower limit for the page content before it moves to the next page

    for i, (file, timestamp) in enumerate(modified_files):
        file_name = os.path.basename(file)  # Get the file name without the path
        c.drawString(100, y_position, file_name)
        c.drawString(400, y_position, time.ctime(timestamp))
        y_position -= 20  # Move down for the next row

        # Check if we need to move to a new page
        if y_position <= max_y_position:
            c.showPage()  # Create a new page
            # Reset the Y position and re-add the header for the new page
            c.setFont("Helvetica-Bold", 16)
            c.drawString(100, height - 50, "Suspicious Activity Report")
            c.setFont("Helvetica", 12)
            c.drawString(100, height - 70, "Files modified before being locked:")
            c.setFont("Helvetica-Bold", 10)
            c.drawString(100, height - 100, "File Name")
            c.drawString(400, height - 100, "Modification Time")
            y_position = height - 120  # Reset the Y position after a new page

    # Save the PDF to file
    c.save()
    print(f"Report generated: {pdf_filename}")


# File system event handler: This class handles file modification events and tracks suspicious activities.
# It records every file modification along with its timestamp, and if the number of changes exceeds a threshold,
# it locks all the files and generates a PDF report.
class MonitorFolderHandler(FileSystemEventHandler):
    def __init__(self, alert_threshold, time_window, monitored_changes, modified_files, lock_files_fn):
        super().__init__()
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        self.monitored_changes = monitored_changes  # Queue to track changes with timestamps
        self.modified_files = modified_files  # List to track modified files
        self.lock_files_fn = lock_files_fn  # Function to lock files when suspicious activity is detected

    # This method is called when a file is modified in the monitored folder
    def on_modified(self, event):
        # Record the time of modification for every file change
        self.monitored_changes.append(time.time())
        self.modified_files.append((event.src_path, time.time()))  # Store file path and timestamp
        print(f"File modified: {event.src_path}")

        # Generate PDF report every time a file is modified
        generate_pdf_report(self.modified_files)


# Folder monitoring function: This function continuously monitors a specified folder for changes.
# It uses the watchdog library to detect modifications and checks whether the number of changes exceeds the threshold.
# If suspicious activity is detected, it locks all the files and generates a PDF report.
def monitor_folder(folder_path, alert_threshold=10, time_window=5):
    # Setup to store change timestamps and an event handler
    monitored_changes = deque()
    modified_files = []  # To track modified files with timestamps
    event_handler = MonitorFolderHandler(alert_threshold, time_window, monitored_changes, modified_files,
                                         lock_files_in_folder)

    # Set up the observer to monitor the folder
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()

    try:
        while True:
            # Remove timestamps older than the time window
            while monitored_changes and time.time() - monitored_changes[0] > time_window:
                monitored_changes.popleft()

            # Check if the number of changes exceeds the alert threshold
            if len(monitored_changes) > alert_threshold:
                print("Suspicious activity detected! Locking all files.")
                # Lock the files
                file_handles = lock_files_in_folder(folder_path)

                # Clear monitored_changes to prevent repeated alerts
                monitored_changes.clear()

            # Check every second
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# Usage example: The monitor_folder function starts monitoring the folder specified by the environment variables.
# The monitoring continues indefinitely, checking for suspicious activity based on file modification frequency.
folder_to_monitor = os.getenv("FOLDER_PATH")
monitor_folder(folder_to_monitor)
