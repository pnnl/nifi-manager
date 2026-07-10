import requests
from config import Config


def get(url: str, config: Config) -> requests.Response:
    response = requests.get(
        url,
        cert=config.certs,
        verify=config.ca_cert_path if config.verify else None,
    )

    return response


def post(url: str, config: Config, payload: dict) -> requests.Response:
    response = requests.post(
        url,
        cert=config.certs,
        verify=config.ca_cert_path if config.verify else None,
        json=payload,
    )

    return response


def put(url: str, config: Config, payload: dict) -> requests.Response:
    response = requests.put(
        url,
        cert=config.certs,
        verify=config.ca_cert_path if config.verify else None,
        json=payload,
    )

    return response


def delete(url: str, config: Config) -> requests.Response:
    response = requests.delete(
        url,
        cert=config.certs,
        verify=config.ca_cert_path if config.verify else None,
    )

    return response
