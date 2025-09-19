import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import tempfile
import shutil
import json
from urllib.parse import unquote
from urllib.parse import urlparse
import re

def main():
    """
    Ubuntu Image Fetcher

    Principles enforced in this script:
    - Community and respect: helpful messages, non-destructive defaults, avoid overwriting user files
    - Mindful network usage: polite User-Agent and retries, timeouts
    - Safety: content checks, size limits, temp-file writes, duplicate detection
    """

    print("Welcome to the Ubuntu Image Fetcher")
    print("A tool for mindfully collecting images from the web\n")
    
    # Get multiple URLs from user (comma or newline separated)
    urls = input("Please enter one or more image URLs (separated by commas or newlines):\n").replace('\n', ',').split(',')
    urls = [u.strip() for u in urls if u.strip()]

    if not urls:
        print("No URLs provided. Exiting.")
        return

    # Create directory if it doesn't exist
    os.makedirs("Fetched_Images", exist_ok=True)

    # Setup a requests Session with retries and a polite User-Agent
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({'User-Agent': 'UbuntuImageFetcher/1.0 (+https://example.local)'})

    # Safety/config defaults
    MAX_BYTES = 5 * 1024 * 1024  # 5 MB max per image
    ALLOWED_CONTENT_TYPES = ("image/jpeg", "image/png", "image/gif", "image/webp")
    import hashlib
    # metadata file to persist etags and hashes across runs
    metadata_path = os.path.join('Fetched_Images', '.metadata.json')
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r', encoding='utf-8') as mf:
                metadata = json.load(mf)
        else:
            metadata = {'files': {}}
    except Exception:
        # Fail softly: if metadata can't be read, continue with empty metadata
        metadata = {'files': {}}

    def sanitize_filename(name: str) -> str:
        # remove query strings and unsafe chars
        name = name.split('?')[0]
        name = name.strip()
        # allow letters, numbers, dot, dash, underscore
        name = re.sub(r'[^A-Za-z0-9._-]', '_', name)
        # fallback
        if not name:
            return 'downloaded_image'
        return name

    def looks_like_image_magic(b: bytes) -> bool:
        # check common magic bytes for JPEG, PNG, GIF, WEBP
        if b.startswith(b"\xFF\xD8\xFF"):  # JPEG
            return True
        if b.startswith(b"\x89PNG\r\n\x1a\n"):  # PNG
            return True
        if b.startswith(b"GIF87a") or b.startswith(b"GIF89a"):  # GIF
            return True
        if b[0:4] == b"RIFF" and b[8:12] == b"WEBP":  # WEBP
            return True
        return False

    for url in urls:
        print(f"\nProcessing: {url}")
        try:
            # Build set of existing file hashes and etags to detect duplicates
            existing_hashes = set()
            existing_etags = set()
            # Load hashes from metadata when available (faster)
            for fn, info in metadata.get('files', {}).items():
                sha = info.get('sha256')
                et = info.get('etag')
                if sha:
                    try:
                        existing_hashes.add(bytes.fromhex(sha))
                    except Exception:
                        pass
                if et:
                    existing_etags.add(et)

            # As a fallback, scan files in directory for hashes not present in metadata
            for root, _, files in os.walk('Fetched_Images'):
                for fn in files:
                    if fn == '.metadata.json':
                        continue
                    path = os.path.join(root, fn)
                    try:
                        h = hashlib.sha256()
                        with open(path, 'rb') as fh:
                            for chunk in iter(lambda: fh.read(8192), b''):
                                h.update(chunk)
                        existing_hashes.add(h.digest())
                    except Exception:
                        pass

            # Use the session for robust fetching; set an explicit timeout
            # Response is used as a context manager to ensure proper connection release
            with session.get(url, stream=True, timeout=10) as response:
                # Raise for HTTP errors (4xx/5xx)
                response.raise_for_status()

                # Basic header checks
                content_type = response.headers.get('Content-Type', '').split(';')[0].lower()
                content_length = response.headers.get('Content-Length')
                content_disp = response.headers.get('Content-Disposition')
                content_encoding = response.headers.get('Content-Encoding')
                x_cto = response.headers.get('X-Content-Type-Options')
                etag = response.headers.get('ETag')
                last_mod = response.headers.get('Last-Modified')

                # Normalize etag
                if etag:
                    etag = etag.strip('"')
                if content_type and content_type not in ALLOWED_CONTENT_TYPES:
                    print(f"✗ Skipping: unsupported Content-Type: {content_type}")
                    continue

                # Check content-length early to avoid downloading large files
                if content_length:
                    try:
                        if int(content_length) > MAX_BYTES:
                            print(f"✗ Skipping: Content-Length {content_length} exceeds limit of {MAX_BYTES}")
                            continue
                    except Exception:
                        # ignore parse errors and fall back to streaming check
                        pass

                # If server indicates the payload is encoded (gzip, br, etc.), skip for safety
                if content_encoding and content_encoding.lower() not in ('identity', ''):
                    # Many image endpoints shouldn't use Content-Encoding; skip to be safe
                    print(f"✗ Skipping: unsupported Content-Encoding: {content_encoding}")
                    continue

                # Respect X-Content-Type-Options: nosniff if present
                if x_cto and x_cto.lower() == 'nosniff' and content_type not in ALLOWED_CONTENT_TYPES:
                    print(f"✗ Skipping: server set X-Content-Type-Options: nosniff but Content-Type is {content_type}")
                    continue

                # Quick ETag-based duplicate check (fast, doesn't require download)
                if etag and etag in existing_etags:
                    print("✗ Skipping: duplicate detected via ETag (server indicates same resource already fetched)")
                    continue

                parsed_url = urlparse(url)
                raw_name = os.path.basename(parsed_url.path)
                filename = sanitize_filename(raw_name)
                # Prefer filename from Content-Disposition when provided
                if content_disp:
                    # Try to extract filename* or filename
                    m = re.search(r"filename\*=(?:[\w\-]+)''(?P<f>[^;]+)", content_disp)
                    if m:
                        try:
                            filename = sanitize_filename(unquote(m.group('f')))
                        except Exception:
                            filename = sanitize_filename(m.group('f'))
                    else:
                        m = re.search(r'filename="(?P<f>[^"]+)"', content_disp)
                        if m:
                            filename = sanitize_filename(m.group('f'))
                # ensure a reasonable extension
                base, ext = os.path.splitext(filename)
                if not ext:
                    # try to infer from content-type
                    if content_type == 'image/jpeg':
                        ext = '.jpg'
                    elif content_type == 'image/png':
                        ext = '.png'
                    elif content_type == 'image/gif':
                        ext = '.gif'
                    elif content_type == 'image/webp':
                        ext = '.webp'
                    filename = base + ext

                # prepare temp file then move into final folder to avoid partial files
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    temp_path = tmp.name
                    total = 0
                    CHUNK = 8192
                    first_chunk = None
                    hasher = hashlib.sha256()
                    try:
                        for chunk in response.iter_content(CHUNK):
                            if not chunk:
                                continue
                            if first_chunk is None:
                                first_chunk = chunk
                            total += len(chunk)
                            if total > MAX_BYTES:
                                raise ValueError(f"File exceeds maximum size of {MAX_BYTES} bytes")
                            tmp.write(chunk)
                            hasher.update(chunk)
                    except Exception:
                        # ensure temp file removed on error
                        tmp.close()
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass
                        raise

                file_hash = hasher.digest()
                if file_hash in existing_hashes:
                    # duplicate detected; remove temp and skip
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                    print("✗ Skipping: duplicate image detected (content matches an existing file)")
                    continue

                # quick magic-byte check
                with open(temp_path, 'rb') as fh:
                    head = fh.read(16)
                    if not looks_like_image_magic(head):
                        os.remove(temp_path)
                        print("✗ Skipping: downloaded file does not appear to be a valid image (magic bytes mismatch)")
                        continue

                # finalize filename (avoid overwrite)
                final_path = os.path.join('Fetched_Images', filename)
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(final_path):
                    filename = f"{base}_{counter}{ext}"
                    final_path = os.path.join('Fetched_Images', filename)
                    counter += 1
                shutil.move(temp_path, final_path)
                # add the new file's hash to existing_hashes to prevent duplicates within this run
                existing_hashes.add(file_hash)
                print(f"✓ Successfully fetched: {filename}")
                print(f"✓ Image saved to {final_path}")

                # update metadata for persistence
                try:
                    metadata['files'][filename] = {
                        'sha256': file_hash.hex(),
                        'etag': etag,
                        'last_modified': last_mod,
                        'source_url': url
                    }
                    with open(metadata_path, 'w', encoding='utf-8') as mf:
                        json.dump(metadata, mf, indent=2)
                except Exception:
                    # non-fatal
                    pass
        except requests.exceptions.Timeout:
            print("✗ Connection error: request timed out")
        except requests.exceptions.TooManyRedirects:
            print("✗ Connection error: too many redirects")
        except requests.exceptions.SSLError as e:
            print(f"✗ Connection error: SSL error: {e}")
        except requests.exceptions.ConnectionError as e:
            print(f"✗ Connection error: {e}")
        except requests.exceptions.RequestException as e:
            # Catch-all for other requests exceptions
            print(f"✗ Connection error: {e}")
        except ValueError as e:
            print(f"✗ Skipped: {e}")
        except Exception as e:
            print(f"✗ An error occurred: {e}")
    print("\nAll downloads complete. Connection strengthened. Community enriched.")

if __name__ == "__main__":
    main()