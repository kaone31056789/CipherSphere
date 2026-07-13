"""WSGI entry point used by production application servers."""

from ciphersphere import create_app

app = create_app()
