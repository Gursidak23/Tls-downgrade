"""Centralised logging with colour support via colorama."""

import logging
import sys

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

_LEVEL_COLORS = {
    logging.DEBUG:    Fore.CYAN,
    logging.INFO:     Fore.GREEN,
    logging.WARNING:  Fore.YELLOW,
    logging.ERROR:    Fore.RED,
    logging.CRITICAL: Fore.RED + Style.BRIGHT,
}


class ColorFormatter(logging.Formatter):
    def format(self, record):
        colour = _LEVEL_COLORS.get(record.levelno, "")
        record.levelname = f"{colour}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColorFormatter(
            "%(asctime)s  %(levelname)-18s  %(name)s  %(message)s",
            datefmt="%H:%M:%S",
        ))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
