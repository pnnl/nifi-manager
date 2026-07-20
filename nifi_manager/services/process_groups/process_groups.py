from config import Config, get_config
from methods import get
import logging

logger = logging.getLogger(__name__)

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.process_group_path


def get_root_pg_id() -> str:
    try:
        response = get(URL + "/root", CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path)
        r = response.json()
        root_pg_id = r["processGroupFlow"]["id"]
        return root_pg_id

    except Exception as e:
        logger.error("could not get root_pg_id: ", e)
        raise
