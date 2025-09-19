# imager
# Ubuntu Image Fetcher

A Python script for securely and efficiently downloading images from the web while respecting community guidelines and network resources.

## Features

- **Multiple URL Support**: Process multiple image URLs in a single run
- **Duplicate Detection**: Uses ETag headers and SHA256 hashing to avoid duplicate downloads
- **Safety Checks**: Validates content type, file size, and image integrity
- **Network Resilience**: Built-in retry mechanism for failed requests
- **File Preservation**: Never overwrites existing files; uses incremental naming
- **Metadata Tracking**: Maintains download history between sessions

## Requirements

- Python 3.6+
- Requests library

## Installation

1. Clone or download the script
2. Install required dependencies:
```bash
pip install requests
```

## Usage

Run the script and provide image URLs when prompted:
```bash
python imager.py
```

Enter one or more image URLs separated by commas or newlines. The script will:
- Validate each URL
- Check for duplicates
- Download images to a `Fetched_Images` directory
- Preserve metadata for future sessions

## Safety Features

- Limits maximum file size (5MB per image)
- Validates content types (JPEG, PNG, GIF, WEBP)
- Checks image magic bytes for format validation
- Uses secure temporary files during download
- Implements polite User-Agent string

## Output

All images are saved to the `Fetched_Images` directory with sanitized filenames. The script maintains a `.metadata.json` file in this directory to track downloaded content between sessions.

## Notes

- The script is designed to be non-destructive and community-friendly
- Network timeouts are implemented to prevent hanging requests
- All downloads are verified for integrity before saving
- Temporary files are properly cleaned up in case of errors
