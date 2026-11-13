import os
import tempfile


def ensure_private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def restrict_wallet_file(path):
    if os.path.exists(path):
        os.chmod(path, 0o600)


def write_private_file(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary_path = tempfile.mkstemp(prefix='.qrl-wallet-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as outfile:
            outfile.write(data)
            outfile.flush()
            os.fsync(outfile.fileno())
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
