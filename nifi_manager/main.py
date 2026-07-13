import logging
from config import get_config
from manager import NifiManager

if __name__ == "__main__":
    config = get_config()
    logging.basicConfig(
        level=config.log_level,
        format=f"%(asctime)s - %(name)-17s - %(levelname)-8s - {'DRY_RUN - ' if config.dry_run else ''}%(message)s",
    )
    logger = logging.getLogger("Nifi User Manager")
    logging.getLogger("urllib3").setLevel(
        logging.WARNING
    )  # urllib3 debug logging is too noisy

    nifi_user_manager = NifiManager(config, logger)

    changes, failures = nifi_user_manager.run()
    if len(failures) != 0:
        logger.info(f"some errors occured: ")
        for error in failures:
            logger.error(error)
    else:
        logger.info(f"successfully synced nifi acl")
        if len(changes) != 0:
            logger.info("changes: ")
            for change in changes:
                logger.info(f"\t  {change}")
        else:
            logger.info("no changes were made")
