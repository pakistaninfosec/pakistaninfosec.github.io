import time
import random
import logging
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]


def build_session(retries: int = 3, backoff: float = 1.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def random_headers(extra: Optional[dict] = None) -> dict:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        headers.update(extra)
    return headers


def polite_delay(min_s: float = 1.5, max_s: float = 3.5) -> None:
    time.sleep(random.uniform(min_s, max_s))


def safe_get(
    session: requests.Session,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = 15,
    logger: Optional[logging.Logger] = None,
) -> Optional[requests.Response]:
    log = logger or logging.getLogger("utils")
    try:
        resp = session.get(
            url,
            params=params,
            headers=headers or random_headers(),
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp
    except requests.exceptions.HTTPError as e:
        log.warning("HTTP error for %s: %s", url, e)
    except requests.exceptions.ConnectionError as e:
        log.warning("Connection error for %s: %s", url, e)
    except requests.exceptions.Timeout:
        log.warning("Timeout for %s", url)
    except Exception as e:
        log.warning("Unexpected error for %s: %s", url, e)
    return None
