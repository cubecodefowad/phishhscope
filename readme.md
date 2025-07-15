# PhishScope 🐟🔍

PhishScope is a simple web app that scans email attachments using the VirusTotal API and reports if they are potentially malicious or suspicious.

## Features

- Upload any file to check againsts VirusTotal's threat database
- Instant report if known
- Easy to use web interface

## Setup

```bash
git clone https://github.com/cubecodefowad/phishhscope.git
cd phishscope
pip install -r requirements.txt
python app.py

```

## Environment Variables

Set your VirusTotal API key as an environment variable before running the app:

On Linux/macOS:
```
export VT_API_KEY=your_virustotal_api_key
```
On Windows (CMD):
```
set VT_API_KEY=your_virustotal_api_key
```
On Windows (PowerShell):
```
$env:VT_API_KEY="your_virustotal_api_key"
```

You can also use a `.env` file with a tool like `python-dotenv` for local development.

## Production Deployment

1. **Install Gunicorn**
   ```
   pip install gunicorn
   ```
2. **Run with Gunicorn**
   ```
   gunicorn -w 4 -b 0.0.0.0:8000 app:app
   ```
3. **Set Environment Variables**
   - Use a `.env` file in your project root (see above for `VT_API_KEY`).
   - Or set variables in your deployment environment.
4. **Nginx Reverse Proxy (Recommended)**
   - Use Nginx to serve HTTPS and proxy to Gunicorn.
   - Example Nginx config:
     ```nginx
     server {
         listen 80;
         server_name yourdomain.com;
         location / {
             proxy_pass http://127.0.0.1:8000;
             proxy_set_header Host $host;
             proxy_set_header X-Real-IP $remote_addr;
             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
             proxy_set_header X-Forwarded-Proto $scheme;
         }
     }
     ```
   - Use [Certbot](https://certbot.eff.org/) to set up HTTPS certificates.
5. **Security Tips**
   - Never run with Flask’s built-in server in production.
   - Set strong file size/type limits (already in code).
   - Monitor logs for abuse.
   - Keep your `.env` and secrets secure.
