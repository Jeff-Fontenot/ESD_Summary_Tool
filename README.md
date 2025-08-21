# ESD Summary Tool

A PowerShell automation script designed for Marine Corps Enterprise Service Desk (ESD) analysts to quickly retrieve user, workstation, and printer information from Active Directory without navigating multiple administrative interfaces.

## 🎯 Problem Solved

As an ESD analyst, retrieving basic information about users, workstations, or printers typically requires:
- Logging into multiple administrative consoles
- Navigating between 4+ different screens per lookup
- Several minutes per call just to gather basic information

**This script consolidates those lookups into a single, menu-driven interface that delivers comprehensive summaries in seconds.**

## ✨ Features

- **User Summary**: Look up users by username or email, get comprehensive AD info including group memberships, O365/Adobe licensing, and Exchange attributes
- **Printer Summary**: Find AD print queues and map to local printer status
- **Workstation Summary**: Search computers by name or serial number with smart search (exact → prefix → contains)
- **System Resources**: Quick CPU and memory usage for analyst workstations
- **Clipboard Integration**: All summaries can be automatically copied to clipboard for easy pasting into tickets
- **Grid Selection**: Interactive selection when multiple results are found
- **Fast Performance**: Optimized AD queries with efficient search patterns

## 📋 Requirements

- PowerShell 7.3+ (tested on 7.3.1)
- Active Directory PowerShell module (RSAT)
- Domain-joined machine with appropriate AD read permissions
- Windows environment with clipboard access

## 🚀 Installation

1. Download `ESD-Summary.ps1` to your preferred location (recommended: `C:\Scripts\`)
2. Ensure execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Run the script:
   ```powershell
   # From the script directory
   .\ESD-Summary.ps1
   
   # From anywhere (update path as needed)
   & "C:\Scripts\ESD-Summary.ps1"
   ```

## 📖 Usage

The script launches an interactive menu with 5 options:

<img width="1111" height="289" alt="image" src="https://github.com/user-attachments/assets/44692604-e25e-4fec-9471-125db79292f8" />



### 1. User Summary

Search for users by:
- Username (sAMAccountName)
- Email address
- UPN (User Principal Name)

**Example output:**
- Display name, email, employee ID
- Account status (enabled/disabled, locked out)
- Last logon date and account expiration
- OU path and description
- Office 365 and Adobe group memberships
- Exchange attributes and proxy addresses


### 2. Printer Summary

Look up print queues in Active Directory and correlate with local printer status.

**Returns:**
- Printer name and server
- Driver information
- IP address and physical location
- Current status (if locally installed)


### 3. Workstation Summary

Smart computer search supporting:
- Exact computer name matching (fastest)
- Serial number lookup
- Prefix matching (fast)
- Contains matching (comprehensive)

**Provides:**
- Computer name and enabled status
- Serial number (cleaned format)
- Operating system and version
- IPv4 address (resolved via DNS)
- Last logon date and OU path



### 4. System Resources

Quick snapshot of analyst workstation performance:
- CPU usage percentage
- Memory usage and availability
- Total and free memory in GB

<img width="998" height="417" alt="image" src="https://github.com/user-attachments/assets/4b3a8401-6e1f-4a0e-8e63-eeef9b80e87d" />


## 🔧 Advanced Usage

### Function-Level Access

All menu functions can be called directly for scripting or advanced use:

```powershell
# Get user info with clipboard copy
Get-EsdUserSummary -Identity "john.doe" -Copy

# Search workstation with grid selection
Get-EsdWorkstationSummary -Query "DESKTOP" -Grid

# Printer lookup
Get-EsdPrinterSummary -PrinterName "HP-LaserJet-B210"

# System resources
Get-EsdSystemResources
```

### Parameters

- `-Copy`: Automatically copy formatted summary to clipboard
- `-Grid`: Show interactive picker when multiple results found
- `-SearchBase`: Limit workstation search to specific OU (faster)
- `-Server`: Specify domain controller for queries

## 💡 Tips for Best Performance

1. **Workstation searches**: Use exact computer names when possible for fastest results
2. **User lookups**: Email addresses work as well as usernames
3. **Clipboard feature**: Use `-Copy` switch to automatically format results for ticket updates
4. **Grid selection**: Enable `-Grid` for interactive selection when searching with partial terms

## 🤝 Real-World Impact

- **Deployed by 12+ analysts** on first day of release
- **Saves several minutes per call** by eliminating navigation between multiple admin consoles
- **Reduces lookup time from minutes to seconds**
- **Improves ticket accuracy** with comprehensive, formatted summaries
- **Clipboard integration** streamlines documentation workflow

## 📝 Example Workflows

### Typical Help Desk Call
1. User calls with printer issue
2. Run script → Option 2 (Printer Summary)
3. Enter printer name → get IP, location, driver info instantly
4. Results auto-copied to clipboard for ticket documentation
5. **Time saved: 3-4 minutes per call**

### User Account Investigation
1. Security team requests user info
2. Run script → Option 1 (User Summary)
3. Enter email or username
4. Get comprehensive AD summary including groups and attributes
5. **Eliminates need to check multiple AD consoles**

## 🔄 Version History

- **v2.0** (8/19/2025): Complete refactor for speed, safety, and reusability
- **v1.0**: Initial release with basic lookup functionality

## 🏗️ Technical Details

- **Language**: PowerShell 7.3+
- **Dependencies**: ActiveDirectory module
- **Architecture**: Function-based with central menu system
- **Error Handling**: Comprehensive try/catch with user-friendly messages
- **Performance**: Optimized LDAP queries with smart search patterns

## 📄 License

This project is provided as-is for educational and operational use within appropriate organizational contexts.

## 🤝 Contributing

This tool was developed for a specific environment but could be adapted for other organizations. Feel free to fork and modify for your needs.

## 💬 Feedback

As an ESD analyst tool built by an analyst, feedback from other help desk professionals is always welcome. If you adapt this for your environment, I'd love to hear about your experience!

---

*Built with ❤️ for the Marine Corps Enterprise Service Desk community*
