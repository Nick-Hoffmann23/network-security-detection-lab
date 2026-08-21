import json


def load_config():
    with open("config.json", "r") as config_file:
        config = json.load(config_file)

    validate_config(config)
    return config 


def validate_config(config):
    required_keys = ["FAILED_CONNECTION_THRESHOLD", "PORT_SCAN_THRESHOLD", "MIN_ALERT_LEVEL", "FAILED_TARGET_THRESHOLD"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration key: {key}")

    if not isinstance(config["FAILED_CONNECTION_THRESHOLD"], int) or config["FAILED_CONNECTION_THRESHOLD"] < 0:
        raise ValueError("FAILED_CONNECTION_THRESHOLD must be a non-negative integer")

    if not isinstance(config["PORT_SCAN_THRESHOLD"], int) or config["PORT_SCAN_THRESHOLD"] < 0:
        raise ValueError("PORT_SCAN_THRESHOLD must be a non-negative integer")

    valid_alert_levels = ["Low", "Medium", "High", "Critical"]
    if config["MIN_ALERT_LEVEL"] not in valid_alert_levels:
        raise ValueError(f"MIN_ALERT_LEVEL must be one of {valid_alert_levels}")

    if not isinstance(config["FAILED_TARGET_THRESHOLD"], int) or config["FAILED_TARGET_THRESHOLD"] < 0:
        raise ValueError("FAILED_TARGET_THRESHOLD must be a non-negative integer")