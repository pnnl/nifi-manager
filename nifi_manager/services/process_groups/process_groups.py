from config import Config, get_config
from utils import get

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.process_group_path


def get_root_pg_id() -> str:
    response = get(URL + "/root", CONFIG)
    try:
        status_code = response.status_code
        if status_code == 200:
            r = response.json()
            root_pg_id = r["processGroupFlow"]["id"]
            return root_pg_id
        else:
            raise ValueError(f"response code not 200: {status_code}")

    except Exception as e:
        raise ValueError("something went wrong")
