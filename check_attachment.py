import os
import requests
import hashlib

VT_API_KEY = os.environ.get("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("VirusTotal API key not set. Please set the VT_API_KEY environment variable.")

def get_file_hash(file_stream):
    # file_stream should be at position 0
    data = file_stream.read()
    file_stream.seek(0)
    return hashlib.sha256(data).hexdigest()

def scan_file(file_stream, filename):
    # file_stream should be at position 0
    file_hash = get_file_hash(file_stream)
    headers = {"x-apikey": VT_API_KEY}
    report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    # Check if file hash is known
    r = requests.get(report_url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        return {
            "file": filename,
            "malicious": malicious,
            "suspicious": suspicious,
            "explanation": f"This file was flagged by {malicious + suspicious} security engines.",
            "link": f"https://www.virustotal.com/gui/file/{file_hash}/detection"
        }

    # Upload file to VirusTotal
    file_stream.seek(0)
    files = {"file": (filename, file_stream)}
    upload = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

    if upload.status_code == 200:
        upload_data = upload.json()
        analysis_id = upload_data['data']['id']
        return {
            "file": filename,
            "status": "Uploaded for analysis",
            "note": "File is being analyzed...",
            "link": f"https://www.virustotal.com/gui/file/{file_hash}/detection",
            "analysis_id": analysis_id
        }

    return {"error": "VirusTotal scan failed", "status_code": upload.status_code}
