import os
import tempfile

# Tests never touch the real data volume.
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="tgv-test-"))
os.environ.setdefault("TGV_DB_NULLPOOL", "1")

import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Tests log in many times from one address; each test starts with a fresh limiter."""
    from tgviewer.main import login_limiter
    login_limiter.reset()
    yield
