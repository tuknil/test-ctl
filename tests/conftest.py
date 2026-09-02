"""Shared test isolation for durable capability storage."""

from __future__ import annotations

import os

import pytest

# Test collection imports the application and initializes cached settings.
# Force offline fixture behavior before any application module is imported so
# a developer's ignored .env cannot trigger live inference or shared storage.
os.environ["RUN_MODE"] = "fixture"
os.environ["PERSISTENCE_BACKEND"] = "sqlite"
os.environ["DATABASE_PATH"] = f"/tmp/control_translation_pytest_{os.getpid()}.db"

from control_translation import api
from control_translation.persistence import SQLiteRunRepository


@pytest.fixture(autouse=True)
def isolated_api_repository(tmp_path, monkeypatch):
    """Prevent tests from reading or writing a developer's local database."""
    repository = SQLiteRunRepository(tmp_path / "control_translation_test.db")
    repository.initialize()
    monkeypatch.setattr(api, "_REPOSITORY", repository)
    return repository
