from flask import Flask, Response, request
from flask_limiter import Limiter
import requests
import traceback
import re


class ProxyApp:
    """
    A Flask application for proxying content from an external URL.
    """

    def __init__(self):
        self.app = Flask(__name__)
        self.limiter = Limiter(
            app=self.app,
            key_func=lambda: request.remote_addr,  # Rate limit by IP address
            default_limits=["2000 per minute", "60 per second"]
        )

        self.trace = lambda code: (f"<pre>\n{traceback.format_exc()}</pre>", code,) \
            if self.app.debug else ("Error %d" % code, code,)

        self.yt_domain: str = "youtube.com"
        self.allow_hosts: tuple[str] = (
            'accounts.google.com', 'apis.google.com', 'client-channel.google.com',
            'clients4.google.com', 'developers.google.com', 'docs.google.com',
            'families.google.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
            'i.ytimg.com', 'jnn-pa.googleapis.com', 'myaccount.google.com',
            'play.google.com', 'ssl.gstatic.com', 'support.google.com',
            'www.google.com', 'www.google.com.ua', 'www.google.ru', 'www.google.by',
            'www.google.kz', 'www.googletagmanager.com', 'www.gstatic.com',
            'yt3.ggpht.com', 'googleads.g.doubleclick.net', 'static.doubleclick.net',
        )
        self.trackers_endswith: tuple[str] = (
            "/log", "/stats/qoe", "/log_event", "/ptracking"
        )
        self.trackers_f: tuple[str] = (
            "doubleclick.net", "/pagead/",
        )

    def __is_allowed_host(self, url: str) -> bool | None:
        """
        Check if a given URL's host is allowed based on a list of allowed hosts.

        Args:
            url (str): The URL to check.

        Returns:
            bool or None: 
                - True if the URL's host is in the list of allowed hosts.
                - False if the URL's host is not in the list of allowed hosts.
                - None if there is no match found in the URL (e.g., if the URL is not properly formatted).
        """
        match_ = re.search(r'https?://([^:/]+)', url)
        if match_:
            return match_.group(1) in self.allow_hosts

    @staticmethod
    def __remove_cookie(cookie: str, cookie_full: str) -> str:
        """
        Remove a specific cookie from a full cookie string.

        Args:
            cookie (str): The name of the cookie to remove.
            cookie_full (str): The full cookie string.

        Returns:
            str: The modified cookie string with the specified cookie removed.
        """
        pattern: re.Pattern[str] = re.compile(rf'{cookie}=[^;]*;?\s*')
        return re.sub(pattern, "", cookie_full)
    
    def __replace_url(self, match: re.match) -> str:
        """
        Replace a matched URL with an appropriate replacement based on the request host.

        Args:
            match (re.match): A regular expression match object representing a URL.

        Returns:
            str: The replaced URL.
        """
        url: str = match.group(0)
        return url if (url == request.host_url[:-1]) or (
            not self.__is_allowed_host(url)
        ) else request.host_url + url
    
    def __replace_scheme(self, match: re.match) -> str:
        """
        Replace the scheme (HTTP/HTTPS) in a matched URL with an appropriate replacement.

        Args:
            match (re.match): A regular expression match object representing a URL with an HTTP scheme.

        Returns:
            str: The replaced URL with the scheme adjusted based on allowed hosts.
        """
        return "%s%s/%s%s" % (
            match.group(1), 
            match.group(2), 
            match.group(3)[1:].replace('http://', 'https://') if self.__is_allowed_host(match.group(2)) else match.group(3), 
            match.group(4)
        )

    def __fetch_and_proxy(
            self, external_url: str, method: str = "GET", 
            params: dict | None = None, 
            headers: dict | None = None, 
            data: bytes | None = None
        ) -> Response | tuple:
        """
        Fetch content from an external URL and proxy it to the client.

        Args:
            external_url (str): The URL of the external content to proxy.
            method (str, optional): The HTTP method to use for the request (default is "GET").
            params (dict, optional): A dictionary of query parameters to include in the request (default is None).
            headers (dict, optional): A dictionary of HTTP headers to include in the request (default is None).
            data (bytes, optional): Data sent in the post-request

        Returns:
            Flask response or tuple: 
                - If the request is successful, returns a Flask response containing the proxied content.
                - If there's an error during the request, returns a tuple with an error message and an appropriate
                  HTTP status code (400 for request error, 500 for other errors).
        """
        try:
            if external_url.endswith(self.trackers_endswith) or any([(f in external_url) for f in self.trackers_f]):
                return "", 204

            if not params:
                params = {}
            if "key" not in params.keys():
                if headers:
                    headers = {
                        key: re.sub(
                            r":\d+", "", value.replace(
                                request.host, self.yt_domain
                            ))
                            .replace("http://", "https://")
                            .replace(f"//{self.yt_domain}", f"//www.{self.yt_domain}")
                        for key, value in dict(headers).items()
                    }
                    headers["Host"] = f"www.{self.yt_domain}"
                    """"""
                    headers["Cookie"] = self.__remove_cookie("session", headers["Cookie"]) \
                        if "Cookie" in headers.keys() else None

                match_url_host = re.search(r'(https?://)?([^:/]+)(:\d+)?', external_url)
                if match_url_host:
                    headers["Host"] = match_url_host.group(2)

            else:
                headers = None

            if params:
                params = {
                    key: value.replace(request.host, self.yt_domain) 
                    for key, value in dict(params).items()
                }

            if method == "POST":
                requests.request(
                    method="OPTIONS",
                    url=external_url,
                    headers={
                        # "authority": "jnn-pa.googleapis.com", 
                        "accept": "*/*", 
                        "access-control-request-headers": "content-type,x-goog-api-key,x-user-agent", 
                        "access-control-request-method": "POST", 
                        "cache-control": "no-cache", 
                        "origin": f"https://www.{self.yt_domain}", 
                        "pragma": "no-cache", 
                        "referer": f"https://www.{self.yt_domain}/", 
                        "sec-fetch-dest": "empty", 
                        "sec-fetch-mode": "cors", 
                        "sec-fetch-site": "cross-site", 
                        "user-agent": headers["User-Agent"] if (headers and "User-Agent" in headers.keys()) else None
                    },
                    timeout=3
                )

            response = requests.request(
                method=method, 
                url=external_url, 
                params=params, 
                headers=headers,
                data=data,
                allow_redirects=False, 
                timeout=5
            )

            response.headers = {
                key: value.replace(self.yt_domain, request.host)
                for key, value in response.headers.items()
                if key not in ("Transfer-Encoding", "Content-Encoding",)
            }

            if "Location" in response.headers.keys():
                response.headers["Location"] = \
                    re.sub(
                        r'(https?://[\w.-]+(?::\d+)?)', 
                        self.__replace_url, response.headers["Location"]
                    )

            # content process
            content: bytes = response.content
            c_type: str = response.headers.get("Content-Type")
            if c_type:
                if c_type.split("/")[0] in ("text", "application",):
                    domain_pattern: re.Pattern[str] = re.compile(r'\b(www\.)?youtube\.com\b')
                    content: str = re.sub(domain_pattern, request.host, response.text)

                    if request.scheme == "http":
                        content = content.replace(f"https://{request.host}", request.host_url[:-1])

                    content: str = re.sub(r'(https?://[\w.-]+(?::\d+)?)', self.__replace_url, content)

                    if request.url.endswith(("base.js", "desktop_polymer_enable_wil_icons.js",)):
                        content: str = re.sub(r'(?<=\s|")//(.*?)(?=\s|"|$)', request.host_url+r'https://\1', content)

                    content: str = re.sub(r'(http://)([^/]+)(/http://)([^/]+)', self.__replace_scheme, content)

            # Create a Flask response with the decoded content and headers
            proxied_response = Response(
                response=content,
                status=response.status_code,
                headers=response.headers
            )

            return proxied_response

        except requests.exceptions.RequestException as e:
            return self.trace(400)
        
        except Exception as e:
            return self.trace(500)

    def run(self):
        """
        Start the Flask application.
        """
        @self.app.route('/<path:path>', methods=("GET", "POST", "HEAD", "OPTIONS",))
        def proxy(path: str) -> Response:
            """
            Handle requests to proxy content from an external URL.

            Args:
                path (str): The path component of the requested URL.

            Returns:
                Flask response: A Flask response containing the proxied content or an error message.
            """
            yt_d = f"https://www.{self.yt_domain}"

            if (path.startswith(("http://", "https://",))) \
            and(not path.startswith((request.host_url, yt_d,))) \
            :
                if not self.__is_allowed_host(path):
                    return "host not allowed", 403
                external_url: str = path
            else:
                external_url = f"{yt_d}/{path}"

            return self.__fetch_and_proxy(
                external_url, 
                request.method, 
                request.args, 
                request.headers,
                request.data
            )
        
        @self.app.route('/', methods=("GET",))
        def main() -> Response:
            """
            Handle requests to the main endpoint, typically used for proxying the main domain.

            Returns:
                Flask response: A Flask response containing the proxied content or an error message.
            """
            external_url = f"https://www.{self.yt_domain}"

            return self.__fetch_and_proxy(
                external_url,
                request.method, 
                None, 
                request.headers
            )

        self.app.run()


if __name__ == '__main__':
    proxy_app = ProxyApp()
    proxy_app.run()
