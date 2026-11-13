"""Console entry point: `blackarch-ai`."""

from __future__ import annotations


def run() -> None:
    from blackarch_ai.cli.app import app

    app()


if __name__ == "__main__":
    run()
