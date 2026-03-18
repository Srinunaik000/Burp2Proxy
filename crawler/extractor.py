import re
from urllib.parse import urljoin, urlparse, parse_qs

class Extractor:
    """
    Extracts URLs and parameters from HTML and other content.
    """
    # Regex for finding links in href attributes
    HREF_RE = re.compile(r"""href=["'](.*?)["']""", re.IGNORECASE)
    # Regex for finding scripts and images
    SRC_RE = re.compile(r"""src=["'](.*?)["']""", re.IGNORECASE)
    # Regex for finding form actions
    FORM_RE = re.compile(r"""<form\b[^>]*action=["'](.*?)["']""", re.IGNORECASE)
    # Regex for finding input names (including hidden)
    INPUT_RE = re.compile(r"""<input\b[^>]*name=["'](.*?)["'][^>]*>""", re.IGNORECASE)
    # Regex for hidden inputs specifically
    HIDDEN_INPUT_RE = re.compile(r"""<input\b[^>]*type=["']hidden["'][^>]*name=["'](.*?)["'][^>]*>""", re.IGNORECASE)

    @staticmethod
    def extract_links(html, base_url):
        """Extracts all absolute URLs from the HTML content."""
        links = set()
        
        # 1. Extract from href/src
        for pattern in [Extractor.HREF_RE, Extractor.SRC_RE, Extractor.FORM_RE]:
            for match in pattern.finditer(html):
                raw_url = match.group(1)
                # Resolve relative URLs
                absolute_url = urljoin(base_url, raw_url)
                # Remove fragment
                parsed = urlparse(absolute_url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                links.add(clean_url)
        
        return links

    @staticmethod
    def extract_parameters(html, url):
        """
        Analyzes a URL and its HTML content for parameters.
        Returns a dict with 'get_params', 'post_params', and 'hidden_params'.
        """
        results = {
            "url": url,
            "get_params": [],
            "post_params": [],
            "hidden_params": []
        }

        # 1. Extract GET parameters from the URL itself
        parsed_url = urlparse(url)
        if parsed_url.query:
            results["get_params"] = list(parse_qs(parsed_url.query).keys())

        # 2. Extract POST and Hidden parameters from forms in the HTML
        if html:
            # Find all input names
            all_inputs = Extractor.INPUT_RE.findall(html)
            results["post_params"] = list(set(all_inputs))

            # Specifically identify hidden inputs
            hidden_inputs = Extractor.HIDDEN_INPUT_RE.findall(html)
            results["hidden_params"] = list(set(hidden_inputs))

        return results

    @staticmethod
    def is_static_asset(url):
        """Checks if the URL likely points to a other static asset (CSS, JS, images)."""
        static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico', '.pdf')
        parsed = urlparse(url)
        return parsed.path.lower().endswith(static_exts)
