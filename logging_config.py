import logging

from typing import Dict,Any
from logging.config import dictConfig


DEFAULT_LOG_LEVEL:str = 'INFO'
FORMAT: str = "%(levelprefix)s %(message)s"

LOGGING_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
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


def init_logging():
    dictConfig(LOGGING_CONFIG)
    return logging.getLogger("viauatdemo")
