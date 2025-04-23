import click
import psycopg
from flask import current_app as app
from flask import g
from psycopg import IntegrityError
from werkzeug.security import generate_password_hash

from . import migrations, queries


def get_db() -> psycopg.connection.Connection:
    """Singleton function to get the connection to the API database."""

    if "db" not in g:
        g.db = psycopg.connect(
            app.config["DATABASE"], row_factory=psycopg.rows.dict_row
        )

    return g.db


def close_db(e=None):
    """Close the API database connection."""
    db = g.pop("db", None)

    if db is not None:
        db.close()


def create_admin(username: str, password: str):
    """Create an admin user in the database."""
    db = get_db()

    try:
        queries.create_user(
            db,
            username,
            generate_password_hash(password),
            is_admin=True,
            is_internal=True,
            approved=True,
        )
    except IntegrityError:
        print("This user already exists!")
        exit(1)


@click.command("create-admin")
@click.argument("username")
def create_admin_command(username):
    """Create an admin user"""
    password = click.prompt("Enter a password", hide_input=True)
    password2 = click.prompt("Confirm the password", hide_input=True)

    if password != password2:
        click.echo("The passwords must match!")
        raise click.exceptions.Abort

    create_admin(username, password)


@click.command("migrate-db")
def migrate_db():
    """Initialize the database."""
    print("Migrating the database...")
    try:
        with psycopg.connect(app.config["DATABASE"]) as db:
            migrations.migrate(db, migration_dir=app.config["MIGRATION_DIR"])
    except psycopg.OperationalError as e:
        print(f"Failed to migrate: {e}")
        exit(1)


@click.command("list-migrations")
def list_migrations():
    """List all migrations."""
    migrations_ = migrations.list_migrations(app.config["MIGRATION_DIR"])
    for migration in migrations_:
        click.echo(migration)


@click.command("create-migration")
@click.argument("name")
def create_migration(name):
    """Create a new migration."""
    migrations.create_migration(name, migration_dir=app.config["MIGRATION_DIR"])


def init_app(app):
    """Initialize the flask app context for the database."""

    app.teardown_appcontext(close_db)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(migrate_db)
    app.cli.add_command(list_migrations)
    app.cli.add_command(create_migration)