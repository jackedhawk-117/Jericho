# osint_tool.py
# A modular OSINT (Open Source Intelligence) tool in Python.

"""
## OSINT Seeker 🕵️‍♂️

A simple, modular command-line OSINT tool to gather intelligence on various targets.

### Features:
- **Username/Name Check:** Searches for username presence on popular platforms.
- **Photo Analysis:** Extracts EXIF metadata and generates reverse image search links.
- **Document Analysis:** Extracts metadata from PDF/DOCX files and computes file hashes.

### Installation:
1. Save this script as `osint_tool.py`.
2. Create a `requirements.txt` file with the following content:
   requests
   beautifulsoup4
   exifread
   Pillow
   PyPDF2
   python-docx
3. Install the dependencies:
   pip install -r requirements.txt

### Usage Examples:
- **Name/Username:**
  python osint_tool.py --name "johndoe"
- **Photo:**
  python osint_tool.py --photo "path/to/your/image.jpg"
- **Document:**
  python osint_tool.py --document "path/to/your/file.pdf"
- **Combined Query:**
  python osint_tool.py --name "johndoe" --photo "profile_pic.png"
"""

import argparse
import requests
import json
import exifread
import hashlib
import os
from PyPDF2 import PdfReader
from docx import Document

# --- MODULE: Name and Username Search ---

def check_username(username):
    """
    Checks for the existence of a username across a list of social media sites.
    """
    print(f"[+] Checking username: {username}...")
    results = {'username': username, 'found_on': []}
    
    # List of sites with simple username-in-URL structure
    sites = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}"
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for site, url in sites.items():
        try:
            response = requests.get(url, headers=headers, timeout=5)
            # A 200 OK status usually means the profile exists.
            if response.status_code == 200:
                print(f"  [✔] Found on {site}: {url}")
                results['found_on'].append({'site': site, 'url': url, 'status': 'found'})
            else:
                print(f"  [❌] Not found on {site}")
        except requests.RequestException as e:
            print(f"  [!] Error checking {site}: {e}")
            results['found_on'].append({'site': site, 'url': url, 'status': 'error', 'details': str(e)})
            
    return results

# --- MODULE: Photo Analysis ---

def analyze_photo(filepath):
    """
    Extracts EXIF metadata and creates reverse image search links for a photo.
    """
    print(f"[+] Analyzing photo: {filepath}...")
    if not os.path.exists(filepath):
        print(f"  [!] Error: File not found at {filepath}")
        return {"error": "File not found"}

    results = {'filepath': filepath, 'metadata': {}, 'reverse_image_search': {}}

    # 1. Extract EXIF Metadata
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)
            if not tags:
                print("  [-] No EXIF metadata found.")
                results['metadata']['status'] = "No EXIF data found."
            else:
                print("  [✔] Found EXIF Metadata:")
                metadata = {}
                for tag, value in tags.items():
                    if tag not in ('JPEGThumbnail', 'TIFFThumbnail'): # Exclude thumbnail data
                        # Convert value to string to ensure JSON serializability
                        metadata[str(tag)] = str(value)
                        print(f"    - {tag}: {value}")
                results['metadata'] = metadata
    except Exception as e:
        print(f"  [!] Error reading EXIF data: {e}")
        results['metadata']['error'] = str(e)
        
    # 2. Generate Reverse Image Search Links
    print("  [✔] Generated Reverse Image Search Links:")
    base_google_url = "https://images.google.com/searchbyimage?image_url="
    # For a local file, we can't directly link. We provide links to the upload pages.
    # Note: Full automation requires Selenium to upload the file.
    results['reverse_image_search'] = {
        'google': 'https://images.google.com/imghp',
        'tineye': 'https://tineye.com/',
        'yandex': 'https://yandex.com/images/'
    }
    for engine, url in results['reverse_image_search'].items():
        print(f"    - {engine.capitalize()}: {url}")
        
    return results

# --- MODULE: Document Analysis ---

def analyze_document(filepath):
    """
    Extracts metadata and hashes a document file (PDF/DOCX).
    """
    print(f"[+] Analyzing document: {filepath}...")
    if not os.path.exists(filepath):
        print(f"  [!] Error: File not found at {filepath}")
        return {"error": "File not found"}

    results = {'filepath': filepath, 'metadata': {}, 'hashes': {}}
    
    # 1. Extract Metadata based on file type
    try:
        if filepath.lower().endswith('.pdf'):
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                info = reader.metadata
                results['metadata'] = {
                    'author': info.author,
                    'creator': info.creator,
                    'producer': info.producer,
                    'subject': info.subject,
                    'title': info.title,
                    'pages': len(reader.pages)
                }
        elif filepath.lower().endswith('.docx'):
            doc = Document(filepath)
            props = doc.core_properties
            results['metadata'] = {
                'author': props.author,
                'created': str(props.created),
                'modified': str(props.modified),
                'last_modified_by': props.last_modified_by,
                'title': props.title
            }
        else:
            results['metadata']['status'] = "Unsupported file type for metadata extraction."
        
        print("  [✔] Extracted Metadata:")
        for key, value in results['metadata'].items():
            print(f"    - {key.capitalize()}: {value}")

    except Exception as e:
        print(f"  [!] Error extracting metadata: {e}")
        results['metadata']['error'] = str(e)

    # 2. Hash the file
    print("  [✔] File Hashes:")
    try:
        hasher_sha256 = hashlib.sha256()
        hasher_md5 = hashlib.md5()
        with open(filepath, 'rb') as f:
            buf = f.read(65536) # Read in 64k chunks
            while len(buf) > 0:
                hasher_sha256.update(buf)
                hasher_md5.update(buf)
                buf = f.read(65536)
        results['hashes'] = {
            'md5': hasher_md5.hexdigest(),
            'sha256': hasher_sha256.hexdigest()
        }
        print(f"    - MD5: {results['hashes']['md5']}")
        print(f"    - SHA256: {results['hashes']['sha256']}")
    except Exception as e:
        print(f"  [!] Error hashing file: {e}")
        results['hashes']['error'] = str(e)

    # Note: VirusTotal integration would go here. It requires an API key.
    # See "How to Add a New Module" section for an example.
    
    return results

# --- Main Execution and Output Formatting ---

def display_summary(data):
    """
    Prints a clean summary of the collected data to the terminal.
    """
    print("\n" + "="*50)
    print("          OSINT Seeker Report Summary")
    print("="*50)
    for key, value in data.items():
        print(f"\n## {key.replace('_', ' ').title()} ##")
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key == 'found_on':
                    print(f"  - {sub_key.replace('_', ' ').title()}:")
                    for item in sub_value:
                        if item['status'] == 'found':
                           print(f"    - [✔] {item['site']}: {item['url']}")
                else:
                    print(f"  - {sub_key.replace('_', ' ').title()}: {sub_value}")
        else:
            print(f"  - {value}")
    print("\n" + "="*50)

def main():
    parser = argparse.ArgumentParser(description="OSINT Seeker - A modular OSINT tool.")
    parser.add_argument("--name", help="A name or username to investigate.")
    parser.add_argument("--photo", help="Path to a photo for analysis.")
    parser.add_argument("--document", help="Path to a document (PDF, DOCX) for analysis.")
    
    args = parser.parse_args()
    
    # Master dictionary to hold all results
    all_results = {}
    
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.name:
        all_results['username_check'] = check_username(args.name)
        
    if args.photo:
        all_results['photo_analysis'] = analyze_photo(args.photo)
        
    if args.document:
        all_results['document_analysis'] = analyze_document(args.document)
        
    # Display the summary in the terminal
    if all_results:
        display_summary(all_results)
        
        # Save the results to a JSON file
        report_filename = "osint_report.json"
        with open(report_filename, 'w') as f:
            json.dump(all_results, f, indent=4)
        print(f"\n[+] Full report saved to {report_filename}")

if __name__ == "__main__":
    main()