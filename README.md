# 🔐 Encrypted Notes Manager

A modern, secure, password-based encrypted notes manager with CLI and REST API interfaces.
Built with clean code principles and modern Python practices.

## ✨ Features

- 🔒 **Strong Encryption**: AES-128 via Fernet with PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- 🔑 **Pasword Protection**: All notes encrypted with master password
- 💾 **Secure Storage**: Encrypted files with proper permissions (please keep in mind, that it only works on **Unix** machine)
- 🎨 **Rich CLI**: Beautiful terminal interface with Typer + Rich
- 🌐 **REST API**: FastAPI backend for web/mobile frontends
- 🏷️ **Tags & Search**: Organize and find notes easily
- ⭐ **Favorites**: Mark important notes
- 📤 **Import/Export**: Backup and share encrypted notes
- 🗂️ **Archive & Soft Delete**: Organize without losing data
- 📊 **Statistics**: Track your note collection
- 🎨 **Color Coding**: Visual organization with custom colors
- 🔄 **Password Change**: Re-encrypt all notes with new password

## 📦 Getting Started

### Prerequisites

- Python 3.10+
- poetry (highly recommended)

### Using Poetry (recommended)

```bash
git clone https://github.com/yourusername/encrypted-notes.git
cd encrypted-notes

# Install with poetry
poetry install

# Activate virtual environment
poetry shell
```

## 🚀 Quick Start

![CLI Help](docs/cli_help.png)

### 1. Initialize the application

This part is important for CLI and REST API usage.

```bash
cd backend
python3 -m encrypted_notes.cli init

# Custom storage location
python3 -m encrypted_notes.cli init --storage ~/my-secure-notes
```

This creates:

- Config file at `~/.config/encrypted_notes/config.json` (contains salt)
- Storage directory at `~/.config/encrypted-notes/storage/` (encrypted notes)

**Important**: Choose a strong master password! It cannot be recovered if lost.

### 2. Add a new note

```bash
# Opens your default editor ($EDITOR)
python3 -m encrypted_notes.cli.py add --title "My First Note"

# Or provide content inline
python3 -m encrypted_notes.cli.py add --title "Quick Note" --content "Secret information"

# With tags and as favorite
python3 -m encrypted_notes.cli.py add \
  --title "Project Ideas" \
  --tag project \
  --tag ideas \
  --favorite \
  --color "#FF5733"
```

![CLI Add](docs/cli_add.png)

### 3. View notes

```bash
# List all active notes
python3 -m encrypted_notes.cli.py list

# View a specific note by ID
python3 -m encrypted_notes.cli.py view <note-id>
```

![CLI List](docs/cli_list.png)

![CLI View](docs/cli_view.png)

## 🌐 REST API Usage

### Start the server

```bash
# Development mode
python3 -m encrypted_notes.api
```

![API Showcase](docs/api_showcase.png)

## Security Considerations

- ⚠️ **Password Strength**: Use a strong, unique master password (20+ characters recommended)
- ⚠️ **Password Recovery**: If you lose your password, data cannot be recovered
- ⚠️ **API Authentication**: Demo uses simple header auth - not production-ready
- ⚠️ **Local Storage**: Notes stored locally - backup regularly
- ⚠️ **Memory Security**: Decrypted content temporarily in memory

## Not Secure For

- ❌ **Multi-user environments**: No user separation
- ❌ **Network exposure without TLS**: Password transmitted in clear
- ❌ **Shared hosting**: Other users might access storage
- ❌ **Untrusted devices**: Malware could capture password

## Todo List

- [ ] Proper Authentication: Replace header auth with JWT/OAuth2
- [ ] Web frontend
- [ ] Mobile app
- [ ] add HTTPS/TLS
- [ ] Support multi-user environments



⚠️ **Disclaimer**: This software is provided "as is" without warranty. Always backup your data and use strong passwords. The authors are not responsible for data loss.
