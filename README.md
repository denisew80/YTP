[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codebeat badge](https://codebeat.co/badges/d57442c7-9eae-4c04-8d9e-66d7663ec36b)](https://codebeat.co/projects/github-com-koval01-ytproxy-main)

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/koval01/YTproXy/tree/main)
[![Run on Repl.it](https://repl.it/badge/github/koval01/YTproXy)](https://repl.it/github/koval01/YTproXy)

---

# YouTube Web Proxy

This is a simple web proxy based on Python Flask designed to provide easy and convenient access to YouTube in regions where it is blocked.

## Features

- Bypass YouTube restrictions in your region.
- Easy setup and deployment.
- Secure access with HTTPS using Nginx and SSL.

## Prerequisites

Before you get started, make sure you have the following installed:

- Python >=3.11
- Flask
- Flask-Limiter
- requests
- Nginx
- Waitress (for production deployment)

## Installation

1. Clone this repository to your server:

   ```bash
   git clone https://github.com/koval01/YTproXy.git
   ```

2. Change to the project directory:

   ```bash
   cd YTproXy
   ```

3. Create environment:

   ```bash
   python3 -m venv env && . ./env/bin/activate
   ```

4. Install requirements:

   ```bash
   pip install -U -r requirements.txt
   ```

## Usage

### Running Locally

To run the web proxy locally for testing purposes, simply execute:

```bash
python app.py
```

The proxy will be accessible at `http://localhost:5000`.

### Production Deployment

For production deployment, it's recommended to use a production-ready server like Waitress and Nginx for better performance and security.

#### Install Waitress

```bash
pip install -U waitress
```

#### Configure Nginx

1. Install Nginx if not already installed:

   ```bash
   sudo apt-get update
   sudo apt-get install nginx
   ```

2. Create an Nginx server block configuration file:

   ```bash
   sudo nano /etc/nginx/sites-available/youtube-proxy
   ```

   Add the following configuration, replacing `yourdomain.com` with your actual domain name:

   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;

       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```

3. Create a symbolic link to enable the configuration:

   ```bash
   sudo ln -s /etc/nginx/sites-available/youtube-proxy /etc/nginx/sites-enabled/
   ```

4. Test the Nginx configuration for syntax errors:

   ```bash
   sudo nginx -t
   ```

5. If the configuration test is successful, reload Nginx to apply the changes:

   ```bash
   sudo systemctl reload nginx
   ```

#### Cloudflare Integration

1. Sign up for a Cloudflare account if you don't already have one: [Cloudflare Signup](https://www.cloudflare.com/)

2. Add your domain to Cloudflare and follow their DNS setup instructions.

3. Once your domain is set up on Cloudflare, enable the CDN features like caching, DDoS protection, and SSL/TLS. Refer to Cloudflare's documentation for guidance.

4. In your Cloudflare dashboard, set up a CNAME record to point to your server's domain or IP address. This will enable Cloudflare's CDN for your proxy server.

5. Ensure your domain's DNS settings are configured to use Cloudflare's nameservers.

Your YouTube proxy should now be accessible via your domain name with enhanced performance and security through Cloudflare's CDN.

#### Start the Waitress Server

Start the Waitress server on port 8080:

```bash
waitress-serve --host=127.0.0.1 --port=8080 app:ProxyApp
```

Your YouTube proxy should now be accessible via your domain name with HTTPS.

## Disclaimer

This project is intended for educational and research purposes only. Ensure you comply with all relevant laws and regulations when using this proxy.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
