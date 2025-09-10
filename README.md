
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/neenonsegura/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor” in it and discovered what looks like the user “winlabuser” downloaded a tor installer. They did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-09T20:39:40.0625094Z`. These events began at: `2025-09-09T20:25:35.7727776Z`.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-nee"
| where InitiatingProcessAccountName == "winlabuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-09T20:25:35.7727776Z)
| project  Timestamp, DeviceName, Account = InitiatingProcessAccountName, FolderPath, ActionType, FileName, SHA256
```
<img width="1371" height="493" alt="image" src="https://github.com/user-attachments/assets/5ff4c592-99d2-486d-842b-56a7e11ef44d" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.5.6.exe /S“. Based on the logs that were returned, at `2025-09-09T20:25:35.7727776Z` on a machine named "threat-hunt-nee", user "winlabuser" silently launched Tor Browser Portable version 14.5.6 from their Downloads folder. The application `tor-browser-windows-x86_64-portable-14.5.6.exe` was executed with a /S (silent install) flag.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-nee"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project  Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, ActionType, FileName, SHA256
```
<img width="1444" height="194" alt="image" src="https://github.com/user-attachments/assets/7d2071e8-4dd8-49ab-8fa6-d7a9778326a9" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that the user “winlabuser” actually opened the tor browser. There was evidence that they did open it at `2025-09-09T20:28:18.8707051Z`. There were several other instances of `firefox.exe` as well as `tor.exe` spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-nee"
| where FileName has_any ("tor-browser-windows-x86_64-portable-14.5.6.exe", "tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, ActionType, FileName, SHA256 
| order by Timestamp desc
```
<img width="1639" height="592" alt="image" src="https://github.com/user-attachments/assets/916ea61a-a480-47b2-8dda-fa3f4cd46859" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the `DeviceNetworkEvents` table for any indication that the tor browser was used to establish a connection to any of the known tor ports. At `2025-09-09T20:28:51.7130901Z`,  the computer named “threat-hunt-nee” quietly opened a connection from its Tor process (`tor.exe`) under the user "winlabuser", to the external IP `195.245.203.32`, using port `9001`, which is the default Tor relay port. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\winlabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-nee"
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1676" height="374" alt="image" src="https://github.com/user-attachments/assets/a5e7702d-9176-49dd-9388-a72a8115d63b" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-09T20:25:35.7727776Z`
- **Event:** The user "winlabuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\winlabuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-09T20:25:35.7727776Z`
- **Event:** The user "winlabuser" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe /S`
- **File Path:** `C:\Users\winlabuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-09T20:28:18.8707051Z`
- **Event:** User "winlabuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\winlabuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-09T20:28:51.7130901Z`
- **Event:** A network connection to IP `195.245.203.32` on port `9001` by user "winlabuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\winlabuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-09T20:28:52.3078073Z` - Connected to `51.15.76.56` on port `443`.
  - `2025-09-09T20:28:52.0210026Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "winlabuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-09T20:39:40.0625094Z`
- **Event:** The user "winlabuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\winlabuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "winlabuser" on the "threat-hunt-nee" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-nee` by the user `winlabuser`. The device was isolated, and the user's direct manager was notified.

---
