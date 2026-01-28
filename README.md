#  Directory Explorer

A lightweight, single-file PHP utility for navigating remote server directories, inspecting files, and diagnosing server health. Designed as a "drop-in" rescue tool for developers.

 **This project was developed using various tools, including LLMs**

![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=flat-square&logo=php&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

##  Features

- **Single File Deployment**: No dependencies, no installation. Just drop it in and go.
- **Recursive File Browser**: Navigate your server's file system with a clean, responsive UI.
- **Instant File Viewer**: Safely view code and configuration files (read-only) without downloading them.
- **Server Health Dashboard**:
  - Monitor Disk Usage, Memory Limits, and Max Execution Time.
  - View all loaded PHP Extensions with real-time search.
  - Check Opcache status and PHP API details.
- **Security Focused**:
  - Password authentication (hardcoded).
  - CSRF Protection.
  - Session Fixation Protection.
  - XSS-safe output rendering.
  - Obfuscated temporary filenames recommended.

##  Usage

1. **Download** the `directory_explorer.php` file.
2. **Configure your password** by editing the top of the file:
   ```php
   // CONFIGURATION - Change this password!
   $PASSWORD = 'your-secure-password-here'; 
   ```
3. **Upload** to your server via FTP or SSH.
4. **Access** via your browser (e.g., `https://yourdomain.com/directory_explorer.php`).
5. **Login** and perform your maintenance tasks.

> [!IMPORTANT]
> **DELETE THIS FILE IMMEDIATELY AFTER USE.**
> Leaving a file browser on your production server is a security risk, even with password protection.

## Security

This tool is intended for **temporary use** by authorized administrators. 

- It intentionally allows filesystem traversal.
- It displays sensitive server configuration.
- **Do not** leave it permanently on a public-facing server.
- Renaming the file to something obscure (e.g., `rescue_8x92a.php`) is recommended during use.

### File Explorer
Navigate directories and grab paths quickly.

### Server Health
Diagnose environment issues at a glance.

## License

MIT License. Free to use and modify.
