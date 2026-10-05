"""Shared test fixture: throwaway Ed25519 release keys and signed envelopes
made through the SAME scripts the real publisher uses (scripts/release/),
so a test that passes here is a test of the production signing path.

Requires an Ed25519-capable openssl (scripts/release/openssl-resolve.sh
finds one; LibreSSL on macOS /usr/bin cannot sign Ed25519)."""

import json
import os
import subprocess
import tempfile
import threading
import http.server

HERE = os.path.dirname(os.path.abspath(__file__))
# Tests deliberately break PATH in places; the signing scripts still need
# openssl/python3/coreutils, so they always get the PATH we were born with.
_ORIG_PATH = os.environ.get("PATH", "/usr/bin:/bin")
REPO_ROOT = os.path.dirname(HERE)
RELEASE_SCRIPTS = os.path.join(HERE, "release")


# The channels the production key/sign scripts accept. Any other channel
# name (the retired `ada-cli` / `ada-ut`, or a hostile fixture) is refused
# by those scripts, so the fixture generates and signs such keys DIRECTLY
# with openssl — tests may forge pre-rename or foreign envelopes; the
# production tooling never can.
PRODUCTION_CHANNELS = ("briglia-cli", "briglia-ut")


class TestKey:
    """One generated key pair for a channel, living in a temp dir."""

    def __init__(self, channel):
        self.channel = channel
        self.dir = tempfile.mkdtemp(prefix="briglia-ut-testkey-")
        if channel in PRODUCTION_CHANNELS:
            subprocess.run([os.path.join(RELEASE_SCRIPTS, "release-keygen.sh"),
                            channel, self.dir], check=True, capture_output=True,
                           env=dict(os.environ, PATH=_ORIG_PATH))
            record = next(f for f in os.listdir(self.dir) if f.endswith(".json"))
            with open(os.path.join(self.dir, record)) as f:
                data = json.load(f)
        else:
            data = _raw_keygen(channel, self.dir)
        self.key_id = data["keyId"]
        self.pub_hex = data["publicKeyHex"]
        # `<channel>-release-v1-<fingerprint16>` — the suffix is the key's
        # identity; tests re-derive it under another channel name.
        self.fingerprint = self.key_id.rsplit("-", 1)[1]
        self.priv = os.path.join(self.dir, self.key_id + ".priv.pem")
        self.pub = os.path.join(self.dir, self.key_id + ".pub.pem")

    def keys(self):
        return {self.key_id: self.pub_hex}

    def sign(self, manifest_bytes, channel=None):
        """Envelope bytes for EXACT manifest bytes via sign-envelope.sh (the
        production signer) — or, for a channel the production signer refuses,
        via the raw openssl path with this key's keyId shape."""
        channel = channel or self.channel
        if channel not in PRODUCTION_CHANNELS:
            return raw_envelope(self.priv, manifest_bytes, channel, self.key_id)
        work = tempfile.mkdtemp(prefix="briglia-ut-sign-")
        try:
            manifest_path = os.path.join(work, "manifest.json")
            out_path = os.path.join(work, "manifest.sig.json")
            with open(manifest_path, "wb") as f:
                f.write(manifest_bytes)
            env = dict(os.environ, EXPECTED_PUBKEY_PEM=self.pub, PATH=_ORIG_PATH)
            subprocess.run([os.path.join(RELEASE_SCRIPTS, "sign-envelope.sh"),
                            self.priv, channel, manifest_path, out_path],
                           check=True, capture_output=True, env=env)
            with open(out_path, "rb") as f:
                return f.read()
        finally:
            for name in ("manifest.json", "manifest.sig.json"):
                try:
                    os.unlink(os.path.join(work, name))
                except OSError:
                    pass
            os.rmdir(work)


def _resolve_openssl():
    """The Ed25519-capable openssl the release scripts themselves resolve."""
    out = subprocess.run(
        ["bash", "-c", '. "%s/openssl-resolve.sh" && resolve_openssl && printf "%%s" "$OPENSSL"'
         % RELEASE_SCRIPTS],
        check=True, capture_output=True, text=True,
        env=dict(os.environ, PATH=_ORIG_PATH)).stdout.strip()
    if not out:
        raise RuntimeError("no Ed25519-capable openssl found")
    return out


def _raw_keygen(channel, out_dir):
    """Mirror of release-keygen.sh for channels it refuses: same file
    layout (<keyId>.priv.pem / .pub.pem / .json), same keyId derivation
    (channel-release-v1-<first 16 hex of sha256(raw pub))."""
    import hashlib
    openssl = _resolve_openssl()
    env = dict(os.environ, PATH=_ORIG_PATH)
    tmp_priv = os.path.join(out_dir, ".keygen-tmp.pem")
    subprocess.run([openssl, "genpkey", "-algorithm", "ed25519", "-out", tmp_priv],
                   check=True, capture_output=True, env=env)
    der = subprocess.run([openssl, "pkey", "-in", tmp_priv, "-pubout", "-outform", "DER"],
                         check=True, capture_output=True, env=env).stdout
    raw = der[-32:]
    fingerprint = hashlib.sha256(raw).hexdigest()
    key_id = "%s-release-v1-%s" % (channel, fingerprint[:16])
    priv = os.path.join(out_dir, key_id + ".priv.pem")
    os.rename(tmp_priv, priv)
    os.chmod(priv, 0o600)
    subprocess.run([openssl, "pkey", "-in", priv, "-pubout", "-out",
                    os.path.join(out_dir, key_id + ".pub.pem")],
                   check=True, capture_output=True, env=env)
    data = {"keyId": key_id, "channel": channel, "publicKeyHex": raw.hex(),
            "fingerprintSHA256": fingerprint}
    with open(os.path.join(out_dir, key_id + ".json"), "w") as f:
        json.dump(data, f, indent=2)
    return data


def raw_envelope(priv_pem, payload_bytes, channel, key_id, fmt="ada-release-envelope-v1"):
    """Envelope bytes signed DIRECTLY with openssl over the documented
    domain input — bypassing sign-envelope.sh on purpose, so tests can
    produce envelopes the production signer refuses to make: a retired
    channel name (the pre-rename `ada-ut` live state), a foreign keyId
    shape, a wrong format. Used for transition and hostile fixtures only."""
    import base64
    work = tempfile.mkdtemp(prefix="briglia-ut-rawsign-")
    try:
        message = (fmt.encode() + b"\0" + channel.encode() + b"\0"
                   + key_id.encode() + b"\0" + payload_bytes)
        msg_path = os.path.join(work, "input")
        sig_path = os.path.join(work, "sig")
        with open(msg_path, "wb") as f:
            f.write(message)
        subprocess.run([_resolve_openssl(), "pkeyutl", "-sign", "-rawin", "-inkey", priv_pem,
                        "-in", msg_path, "-out", sig_path],
                       check=True, capture_output=True, env=dict(os.environ, PATH=_ORIG_PATH))
        with open(sig_path, "rb") as f:
            signature = f.read()
        return json.dumps({
            "format": fmt,
            "channel": channel,
            "keyId": key_id,
            "payload": base64.b64encode(payload_bytes).decode(),
            "signature": base64.b64encode(signature).decode(),
        }, indent=2, sort_keys=True).encode()
    finally:
        for name in ("input", "sig"):
            try:
                os.unlink(os.path.join(work, name))
            except OSError:
                pass
        os.rmdir(work)


def manifest_bytes(channel, version, sequence, platforms, published=None,
                   expires=None, schema=1, extra=None):
    """Deterministic manifest JSON bytes in the shape build-manifest.sh
    emits. `platforms` maps name -> {url, size, sha256}."""
    data = {
        "channel": channel,
        "expires": expires or "2099-01-01T00:00:00Z",
        "platforms": platforms,
        "published": published or "2026-01-01T00:00:00Z",
        "schema": schema,
        "sequence": sequence,
        "version": version,
    }
    if extra:
        data.update(extra)
    return json.dumps(data, indent=2, sort_keys=True).encode()


class FakeHost:
    """Tiny HTTP host: path -> (body bytes, declared Content-Length or None
    for honest). Lets tests serve envelopes, artifacts, and liars."""

    def __init__(self):
        self.routes = {}
        self.hits = []
        host = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                host.hits.append(self.path)
                route = host.routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body, declared = route
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length",
                                 str(len(body) if declared is None else declared))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]

    def put(self, path, body, declared_length=None):
        self.routes[path] = (body, declared_length)
        return self.base + path

    def close(self):
        self.server.shutdown()
        self.server.server_close()


PRODUCTION_RELEASES_BASE = "https://github.com/permaevidence/briglia-ut/releases"


def stamp_app_policy(source, key_id, pub_hex, releases_base=None, sequence=None):
    """Return py/release_verify.py text with the APP key replaced by a test
    key and (optionally) the app channel's release location moved from the
    production repository to `releases_base` (…/releases) and the build's
    own APP_RELEASE_SEQUENCE set. The same edit the rehearsal-stamping
    commit makes (scripts/rehearsal/stamp.py); production files are never
    touched by it."""
    import re
    s = re.sub(r"# STAMP-APP-KEY-BEGIN.*?# STAMP-APP-KEY-END",
               '# STAMP-APP-KEY-BEGIN\nAPP_KEYS = {\n    "%s":\n        "%s",\n}\n# STAMP-APP-KEY-END'
               % (key_id, pub_hex), source, flags=re.S)
    if releases_base:
        if PRODUCTION_RELEASES_BASE not in s:
            raise ValueError("production release location not found — refusing to stamp blindly")
        s = s.replace(PRODUCTION_RELEASES_BASE, releases_base)
    if sequence is not None:
        s, n = re.subn(r"^APP_RELEASE_SEQUENCE = \d+$", "APP_RELEASE_SEQUENCE = %d" % sequence, s, flags=re.M)
        if n != 1:
            raise ValueError("APP_RELEASE_SEQUENCE not found exactly once")
    return s
