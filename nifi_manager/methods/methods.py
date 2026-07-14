import time
from typing import Tuple, Dict, Optional
import requests


def get(
    url: str,
    certs: Optional[Tuple[str, str]],
    verify: bool,
    ca_cert_path: Optional[str],
) -> requests.Response:
    response = requests.get(
        url,
        cert=certs,
        verify=ca_cert_path if verify else None,
    )

    response.raise_for_status()

    return response


def post(
    url: str,
    certs: Optional[Tuple[str, str]],
    verify: bool,
    ca_cert_path: Optional[str],
    payload: Dict[str, Dict[str, str]],
) -> requests.Response:
    response = requests.post(
        url,
        cert=certs,
        verify=ca_cert_path if verify else None,
        json=payload,
    )

    response.raise_for_status()

    return response


def put(
    url: str,
    certs: Optional[Tuple[str, str]],
    verify: bool,
    ca_cert_path: Optional[str],
    payload: Dict[str, Dict[str, str]],
) -> requests.Response:
    response = requests.put(
        url,
        cert=certs,
        verify=ca_cert_path if verify else None,
        json=payload,
    )

    response.raise_for_status()

    return response


def delete(
    url: str,
    certs: Optional[Tuple[str, str]],
    verify: bool,
    ca_cert_path: Optional[str],
) -> requests.Response:
    response = requests.delete(
        url,
        cert=certs,
        verify=ca_cert_path if verify else None,
    )

    response.raise_for_status()

    return response


def health(
    url: str,
    certs: Optional[Tuple[str, str]],
    verify: bool,
    ca_cert_path: Optional[str],
) -> bool:
    response = get(url, certs, verify, ca_cert_path)
    response.raise_for_status()

    while response.status_code != 200:
        response = get(url, certs, verify, ca_cert_path)
        response.raise_for_status()

        time.sleep(5)

    return True
