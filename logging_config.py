import logging

from typing import Dict,Any
from logging.config import dictConfig

from const import DEFAULT_LOG_LEVEL

FORMAT: str = "%(asctime)s - %(levelprefix)s %(message)s"

LOGGING_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": FORMAT,
            "use_colors": None,
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "viauatdemo": {"handlers": ["default"], "level": DEFAULT_LOG_LEVEL, "propagate": False},
    },
}

logger = None

def init_logging():
    global logger
    if not logger:
        dictConfig(LOGGING_CONFIG)
        logger = logging.getLogger("viauatdemo")
    return logger
