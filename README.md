# Intune-Master-Report

Cloud Analysis and Reporting for End User Environments (Microsoft Intune).

## Features

- **Multi-Tenant Support**: Manage and generate reports for multiple Microsoft 365 tenants.
- **Automated Reporting**: Generates comprehensive PDF and HTML dashboards of Intune environments.
- **Email Integration**: Send reports directly via Gmail with support for daily scheduling.
- **Secure Storage**: Encrypted session handling and secure tenant configuration.

## Prerequisites

- [Node.js](https://nodejs.org/) (v16 or higher)
- [PowerShell](https://microsoft.com/powershell) (v7+ recommended)
- Microsoft Graph API credentials (Tenant ID, Client ID, Client Secret)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/EndUserRepo.git
   cd EndUserRepo
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

## Running the Application

### Standard Run
```bash
node server.js
```
Access the UI at `http://localhost:3000`.

---

## Deployment Guide

### Windows (Run as a Service)

To run as a background service on Windows, use **pm2**:

1. Install PM2 globally:
   ```powershell
   npm install pm2 -g
   ```
2. Start the application:
   ```powershell
   pm2 start server.js --name "enduser-repo"
   ```
3. (Optional) Install PM2 Windows Startup:
   ```powershell
   npm install pm2-windows-startup -g
   pm2-startup install
   pm2 save
   ```

### macOS (Run as a Service)

1. Install PM2 globally:
   ```bash
   sudo npm install pm2 -g
   ```
2. Start the application:
   ```bash
   pm2 start server.js --name "enduser-repo"
   ```
3. Setup startup script:
   ```bash
   pm2 startup
   # Follow the command output provided by PM2
   pm2 save
   ```

---

## Configuration

- **Tenants**: Managed via `config/tenants.json` or through the web UI.
- **Reports**: Stored in the `reports/` directory.
- **Logs**: Check `app.log` for execution details.

## Security Note

Ensure `config/tenants.json` and `config.json` are added to your `.gitignore` if they contain sensitive production secrets.
