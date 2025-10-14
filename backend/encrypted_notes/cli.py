"""
CLI interface for Encrypted Notes application using Typer.

Commands:
- init: Initialize configuration and storage
- add: Add a new encrypted note
- view: View a decrypted note
- edit: Edit an existing note
- list: List all notes
- search: Search notes
- delete: Delete a note
- archive: Archive a note
- restore: Restore an archived/deleted note
- export: Export a note to file
- import: Import a note from file
- change-password: Change master password
- stats: Show statistics
"""

import json
import os
import subprocess
import tempfile
from getpass import getpass
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from .core import (
    NoteSession,
    create_note,
    read_note,
    update_note,
    delete_note,
    archive_note,
    restore_note,
    list_notes,
    search_notes,
    get_note_statistics,
    get_tags,
    export_note_to_file,
    import_note_from_file,
    change_password,
)
from .models import NoteCreate, NoteUpdate, NoteFilter, NoteStatus
from .storage.file_storage import FileStorage
from .errors import NoteNotFoundError, InvalidPasswordError

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "encrypted-notes"
DEFAULT_STORAGE_DIR = DEFAULT_CONFIG_DIR / "storage"
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"

console = Console()
app = typer.Typer(
    name="encrypted-notes-manager",
    help="Secure encrypted notes manager with password-based encryption",
    add_completion=False,
)


class Config:
    """
    Application configuration
    """

    def __init__(self):
        self.config_dir = DEFAULT_CONFIG_DIR
        self.storage_dir = DEFAULT_STORAGE_DIR
        self.salt_hex: Optional[str] = None
        self.iterations: int = 100_000

    @classmethod
    def load(cls) -> "Config":
        """
        Load configuration from file.
        """
        config = cls()

        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    config.salt_hex = data.get("salt_hex")
                    config.iterations = data.get("iterations", 100_000)

                    if "storage_dir" in data:
                        config.storage_dir = Path(data["storage_dir"])
            except Exception as e:
                console.print(f"[red]Error loading config: {e}[/red]")
                raise typer.Exit(1)

        return config

    def save(self) -> None:
        """
        Save configuration to file.
        """

        self.config_dir.mkdir(parents=True, exist_ok=True)

        data = {
            "salt_hex": self.salt_hex,
            "iterations": self.iterations,
            "storage_dir": str(self.storage_dir),
        }

        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)

        try:
            os.chmod(CONFIG_FILE, 0o600)
            os.chmod(self.config_dir, 0o700)
        except (AttributeError, OSError):
            pass

    def is_initialized(self) -> bool:
        """
        Check if configuration is initialized.
        """
        print(CONFIG_FILE.exists(), self.salt_hex is not None)
        return CONFIG_FILE.exists() and self.salt_hex is not None


def get_config() -> Config:
    """
    Get configuration or exit if not initialized.
    """

    config = Config.load()

    if not config.is_initialized():
        console.print("[red]Not initialized! Run 'encrypted-notes init' first.[/red]")
        raise typer.Exit(1)

    return config


def get_password(confirm: bool = False) -> str:
    """
    Prompt for password securely.
    """

    password = getpass("Enter password: ")

    if not password:
        console.print("[red]Password cannot be empty![/red]")
        raise typer.Exit(1)

    if confirm:
        password2 = getpass("Confirm password: ")
        if password != password2:
            console.print("[red]Passwords don't match![/red]")
            raise typer.Exit(1)

    return password


def create_session(password: Optional[str] = None) -> NoteSession:
    """
    Create a note session with password verification.
    """

    config = get_config()
    storage = FileStorage(config.storage_dir)

    if password is None:
        password = get_password()

    try:
        session = NoteSession.from_salt_hex(
            storage, password, config.salt_hex, config.iterations
        )

        notes = list_notes(session)
        if notes:
            try:
                read_note(session, notes[0].id)
            except InvalidPasswordError:
                console.print("[red]Incorrect password![/red]")
                raise typer.Exit(1)

        return session

    except Exception as e:
        console.print(f"[red]Failed to create session: {e}[/red]")
        raise typer.Exit(1)


def open_editor(initial_content: str = "") -> str:
    """
    Open text editor and return edited content.
    """

    editor = os.environ.get("EDITOR", "vim")

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tf:
        temp_path = Path(tf.name)
        tf.write(initial_content)
        tf.flush()

    try:
        os.chmod(temp_path, 0o600)

        subprocess.run([editor, str(temp_path)], check=True)

        content = temp_path.read_text()

        return content

    finally:
        if temp_path.exists():
            temp_path.unlink()


def format_datetime(dt) -> str:
    """
    Format datetime for display.
    """

    if dt is None:
        return "Never"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def truncate(text: str, length: int = 50) -> str:
    """
    Truncate text with ellipsis.
    """

    if len(text) <= length:
        return text
    return text[: length - 3] + "..."


@app.command()
def init(
    storage_dir: Optional[Path] = typer.Option(
        None, "--storage", "-s", help="Custom storage directory"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Force re-initialization"),
):
    """
    Initialize encrypted notes configuration.

    Creates configuration directory, generates encryption salt,
    and sets up storage. Deletes existing data in storage directory if it exists.
    """

    config = get_config()

    if config.is_initialized() and not force:
        console.print(
            "[yellow]Already initialized! Use --force to re-initialize.[/yellow]"
        )
        raise typer.Exit(0)

    if storage_dir:
        config.storage_dir = storage_dir.absolute()

    config.config_dir.mkdir(parents=True, exist_ok=True)

    if config.storage_dir.exists():
        for item in config.storage_dir.iterdir():
            if item.is_dir():
                for sub_item in item.rglob("*"):
                    sub_item.unlink()
                item.rmdir()
            else:
                item.unlink()

    config.storage_dir.mkdir(parents=True, exist_ok=True)

    console.print("[bold]Set up master password:[/bold]")
    password = get_password(confirm=True)

    storage = FileStorage(config.storage_dir)
    session = NoteSession(storage, password, iterations=config.iterations)

    config.salt_hex = session.get_salt_hex()
    config.save()

    console.print(f"[green]✓[/green] Configuration saved to: {CONFIG_FILE}")
    console.print(f"[green]✓[/green] Storage directory: {config.storage_dir}")
    console.print(f"[green]✓[/green] Salt: {config.salt_hex[:16]}...")
    console.print("\n[bold green]Initialization complete![/bold green]")


@app.command()
def add(
    title: Optional[str] = typer.Option(None, "--title", "-t", help="Note title"),
    content: Optional[str] = typer.Option(
        None, "--content", "-c", help="Note content (or use editor)"
    ),
    tags: Optional[list[str]] = typer.Option(
        None, "--tag", help="Add tags (can be used multiple times)"
    ),
    favorite: bool = typer.Option(False, "--favorite", "-f", help="Mark as favorite"),
    color: Optional[str] = typer.Option(
        None, "--color", help="Note color (hex format, e.g., #FF5733)"
    ),
):
    """
    Add a new encrypted note.

    If content is not provided, opens $EDITOR for input.
    """

    session = create_session()

    if not title:
        title = Prompt.ask("[bold]Note title[/bold]")

    if not content:
        console.print("[dim]Opening editor... (set $EDITOR to change editor)[/dim]")
        content = open_editor()

        if not content.strip():
            console.print("[yellow]Empty content, aborting.[/yellow]")
            raise typer.Exit(0)

    try:
        note_data = NoteCreate(
            title=title,
            content=content,
            tags=tags or [],
            favorite=favorite,
            color=color,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Encrypting and saving...", total=None)
            note = create_note(session, note_data)

        console.print("\n[green]✓[/green] Note created successfully!")
        console.print(f"  ID: [cyan]{note.id}[/cyan]")
        console.print(f"  Title: {note.title}")
        console.print(f"  Size: {note.size_bytes} bytes")
        if note.tags:
            console.print(f"  Tags: {', '.join(note.tags)}")

    except Exception as e:
        console.print(f"[red]Error creating note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def view(
    note_id: str = typer.Argument(..., help="Note ID to view"),
    pager: bool = typer.Option(
        False, "--pager", "-p", help="Use pager for long content"
    ),
):
    """
    View a decrypted note.
    """

    session = create_session()

    try:
        note = read_note(session, note_id)

        panel = Panel(
            note.content,
            title=f"[bold]{note.title}[/bold]",
            subtitle=f"ID: {note.id} | Created: {format_datetime(note.created_at)}",
            border_style="cyan",
        )

        if pager:
            with console.pager():
                console.print(panel)
        else:
            console.print(panel)

        if note.tags:
            console.print(f"Tags: {', '.join(note.tags)}")
        if note.favorite:
            console.print("[yellow]★ Favorite[/yellow]")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except InvalidPasswordError:
        console.print("[red]Incorrect password or corrupted data![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error reading note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def edit(
    note_id: str = typer.Argument(..., help="Note ID to edit"),
    title: Optional[str] = typer.Option(None, "--title", "-t", help="New title"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="Replace tags"),
    add_tags: Optional[list[str]] = typer.Option(None, "--add-tag", help="Add tags"),
    favorite: Optional[bool] = typer.Option(
        None, "--favorite/--no-favorite", help="Set favorite status"
    ),
):
    """
    Edit an existing note.

    Opens editor with current content. You can also update metadata with options.
    """

    session = create_session()

    try:
        note = read_note(session, note_id)

        console.print(f"[dim]Editing note: {note.title}[/dim]")
        console.print("[dim]Opening editor...[/dim]")

        new_content = open_editor(note.content)

        update_data = NoteUpdate(
            title=title,
            content=new_content if new_content != note.content else None,
            tags=tags,
            favorite=favorite,
        )

        if add_tags:
            current_tags = set(note.tags)
            current_tags.update(add_tags)
            update_data.tags = list(current_tags)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Saving changes...", total=None)
            updated = update_note(session, note_id, update_data)

        console.print("\n[green]✓[/green] Note updated successfully!")
        console.print(f"  Title: {updated.title}")
        console.print(f"  Updated: {format_datetime(updated.updated_at)}")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error editing note: {e}[/red]")
        raise typer.Exit(1)


@app.command("list")
def list_cmd(
    status: NoteStatus = typer.Option(
        NoteStatus.ACTIVE, "--status", "-s", help="Filter by status"
    ),
    tag: Optional[list[str]] = typer.Option(None, "--tag", "-t", help="Filter by tags"),
    search: Optional[str] = typer.Option(None, "--search", help="Search in titles"),
    favorites: bool = typer.Option(
        False, "--favorites", "-f", help="Show only favorites"
    ),
    limit: int = typer.Option(
        20, "--limit", "-n", help="Maximum number of notes to show"
    ),
):
    """
    List all notes with metadata.
    """

    session = create_session()

    try:
        note_filter = NoteFilter(
            status=status,
            tags=tag,
            search=search,
            favorite=favorites if favorites else None,
            page_size=limit,
        )

        notes = list_notes(session, note_filter)

        if not notes:
            console.print("[yellow]No notes found.[/yellow]")
            return

        table = Table(title=f"Notes ({len(notes)} found)", show_header=True)
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Title", style="bold")
        table.add_column("Tags", style="dim")
        table.add_column("Created", style="dim")
        table.add_column("Size", justify="right", style="dim")
        table.add_column("Fav", justify="center")

        for note in notes:
            table.add_row(
                note.id[:8] + "...",
                truncate(note.title, 40),
                ", ".join(note.tags[:3]) + ("..." if len(note.tags) > 3 else ""),
                format_datetime(note.created_at).split()[0],
                f"{note.size_bytes}B",
                "★" if note.favorite else "",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error listing notes: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query"),
    in_content: bool = typer.Option(
        False, "--content", "-c", help="Search in note content (slower)"
    ),
):
    """
    Search notes by title or content.
    """

    session = create_session()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            _ = progress.add_task(description="Searching...", total=None)
            results = search_notes(session, query, search_content=in_content)

        if not results:
            console.print(f"[yellow]No notes found matching '{query}'[/yellow]")
            return

        console.print(f"\n[bold]Found {len(results)} note(s):[/bold]\n")

        for note in results:
            console.print(f"[cyan]{note.id}[/cyan] {note.title}")
            if note.tags:
                console.print(f"  Tags: {', '.join(note.tags)}")
            console.print()

    except Exception as e:
        console.print(f"[red]Error searching: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def delete(
    note_id: str = typer.Argument(..., help="Note ID to delete"),
    permanent: bool = typer.Option(
        False, "--permanent", "-p", help="Permanently delete (cannot be restored)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """
    Delete a note (soft delete by default).
    """

    session = create_session()

    try:
        note = read_note(session, note_id)

        if not yes:
            delete_type = "permanently delete" if permanent else "delete"
            if not Confirm.ask(
                f"[yellow]Really {delete_type} '{note.title}'?[/yellow]"
            ):
                console.print("Cancelled.")
                raise typer.Exit(0)

        delete_note(session, note_id, permanent=permanent)

        if permanent:
            console.print(f"[green]✓[/green] Note permanently deleted: {note.title}")
        else:
            console.print(f"[green]✓[/green] Note moved to trash: {note.title}")
            console.print("[dim]Use 'restore' command to recover.[/dim]")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error deleting note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def archive(note_id: str = typer.Argument(..., help="Note ID to archive")):
    """
    Archive a note.
    """

    session = create_session()

    try:
        archived = archive_note(session, note_id)
        console.print(f"[green]✓[/green] Note archived: {archived.title}")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error archiving note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def restore(note_id: str = typer.Argument(..., help="Note ID to restore")):
    """
    Restore an archived or deleted note.
    """

    session = create_session()

    try:
        restored = restore_note(session, note_id)
        console.print(f"[green]✓[/green] Note restored: {restored.title}")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error restoring note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def export(
    note_id: str = typer.Argument(..., help="Note ID to export"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """
    Export a note to a file.
    """

    session = create_session()

    try:
        # Default output path
        if output is None:
            note = read_note(session, note_id)
            safe_title = "".join(
                c for c in note.title if c.isalnum() or c in (" ", "-", "_")
            )
            output = Path(f"{safe_title}_{note_id[:8]}.json")

        export_note_to_file(session, note_id, output)
        console.print(f"[green]✓[/green] Note exported to: {output}")

    except NoteNotFoundError:
        console.print(f"[red]Note {note_id} not found![/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error exporting note: {e}[/red]")
        raise typer.Exit(1)


@app.command("import")
def import_cmd(
    file_path: Path = typer.Argument(..., help="File to import"),
    new_id: bool = typer.Option(
        True, "--new-id/--keep-id", help="Generate new ID or keep original"
    ),
):
    """
    Import a note from a file.
    """

    session = create_session()

    try:
        imported = import_note_from_file(session, file_path, new_id=new_id)
        console.print("[green]✓[/green] Note imported successfully!")
        console.print(f"  ID: [cyan]{imported.id}[/cyan]")
        console.print(f"  Title: {imported.title}")

    except FileNotFoundError:
        console.print(f"[red]File not found: {file_path}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error importing note: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def change_password_cmd():
    """
    Change the master password.

    This will re-encrypt all notes with the new password.
    """

    console.print("[bold]Changing master password[/bold]")
    console.print("[yellow]Warning: This will re-encrypt ALL notes![/yellow]\n")

    console.print("[bold]Enter current password:[/bold]")
    old_password = get_password()

    try:
        session = create_session(old_password)
    except SystemExit:
        console.print("[red]Incorrect current password![/red]")
        raise typer.Exit(1)

    console.print("\n[bold]Enter new password:[/bold]")
    new_password = get_password(confirm=True)

    try:

        def progress_callback(current, total):
            console.print(f"Re-encrypting notes: {current}/{total}", end="\r")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task(description="Re-encrypting all notes...", total=None)
            new_session = change_password(session, new_password, progress_callback)

        config = Config.load()
        config.salt_hex = new_session.get_salt_hex()
        config.save()

        console.print("\n[green]✓[/green] Password changed successfully!")
        console.print("[dim]All notes have been re-encrypted.[/dim]")

    except Exception as e:
        console.print(f"\n[red]Error changing password: {e}[/red]")
        console.print(
            "[yellow]Your notes are still encrypted with the old password.[/yellow]"
        )
        raise typer.Exit(1)


@app.command()
def stats():
    """
    Show statistics about your notes.
    """

    session = create_session()

    try:
        statistics = get_note_statistics(session)

        stats_text = f"""
[bold]Total Notes:[/bold] {statistics.total_notes}
  [green]Active:[/green] {statistics.active_notes}
  [yellow]Archived:[/yellow] {statistics.archived_notes}
  [red]Deleted:[/red] {statistics.deleted_notes}
  [cyan]Favorites:[/cyan] {statistics.favorite_count}

[bold]Storage:[/bold]
  Total size: {statistics.total_size_bytes:,} bytes
  Average: {statistics.total_size_bytes // max(statistics.total_notes, 1):,} bytes/note

[bold]Tags:[/bold] {statistics.total_tags} unique tags
"""

        if statistics.most_used_tags:
            stats_text += "\n[bold]Most used tags:[/bold]\n"
            for tag, count in statistics.most_used_tags[:5]:
                stats_text += f"  • {tag}: {count} notes\n"

        panel = Panel(
            stats_text.strip(), title="[bold]📊 Statistics[/bold]", border_style="cyan"
        )

        console.print(panel)

    except Exception as e:
        console.print(f"[red]Error getting statistics: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def tags():
    """
    List all tags used in notes.
    """
    session = create_session()

    try:
        all_tags = get_tags(session)

        if not all_tags:
            console.print("[yellow]No tags found.[/yellow]")
            return

        console.print(f"[bold]Tags ({len(all_tags)}):[/bold]\n")

        for tag in all_tags:
            console.print(f"  • {tag}")

    except Exception as e:
        console.print(f"[red]Error listing tags: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """
    Show version information.
    """
    console.print("[bold]Encrypted Notes[/bold] v1.0.0")
    console.print("Secure password-based encrypted notes manager")
    console.print("\nFeatures:")
    console.print("  • AES-128 encryption via Fernet")
    console.print("  • PBKDF2-HMAC-SHA256 key derivation")
    console.print("  • Secure file storage with proper permissions")


def main():
    """
    Main entry point.
    """
    app()


if __name__ == "__main__":
    main()
