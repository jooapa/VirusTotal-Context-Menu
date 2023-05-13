import os
import sys
import winreg
import tkinter as tk
import requests
import json
API_KEY = 'api'
API_URL = 'https://www.virustotal.com/vtapi/v2/'

root = tk.Tk()
root.withdraw()

def scan_file(file_path):
    url = API_URL + 'file/scan'
    files = {'file': open(file_path, 'rb')}
    params = {'apikey': API_KEY}
    response = requests.post(url, files=files, params=params)
    return response.json()


def get_report(resource):
    url = API_URL + 'file/report'
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()


def scan_and_show_results(file_path):
    result = scan_file(file_path)
    resource = result['resource']
    report = get_report(resource)

    result_window = tk.Toplevel()
    result_window.title('VirusTotal Result')
    result_text = tk.Text(result_window)
    result_text.pack()

    formatted_report = json.dumps(report, indent=4, sort_keys=True)
    result_text.insert(tk.END, formatted_report)


def add_to_context_menu():
    # Get the path to the executable
    exe_path = sys.executable
    # Create a new registry key for the context menu
    key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '*\\shell\\VirusTotal Scan')
    # Set the command to run when the entry is clicked
    command_key = winreg.CreateKey(key, 'command')
    winreg.SetValueEx(command_key, '', 0, winreg.REG_SZ, f'"{exe_path}" "%1" scan')
    # Set the icon for the entry
    icon_key = winreg.CreateKey(key, 'icon')
    winreg.SetValueEx(icon_key, '', 0, winreg.REG_SZ, f'"{exe_path}",0')
    # Close the registry keys
    winreg.CloseKey(command_key)
    winreg.CloseKey(icon_key)
    winreg.CloseKey(key)


def main():
    if len(sys.argv) == 3 and sys.argv[2] == 'scan':
        # If the script is called from the context menu, scan the file and show the results
        file_path = sys.argv[1]
        print(f'Scanning {file_path}...')
        scan_and_show_results(file_path)
    else:
        # If the script is run without arguments, add the context menu entry
        add_to_context_menu()
        print('VirusTotal Scanner has been added to the context menu.')


if __name__ == '__main__':
    main()
    

root.mainloop()