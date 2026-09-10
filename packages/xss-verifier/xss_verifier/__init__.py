# SPDX-License-Identifier: MIT
"""Shared headless-Chromium victim bot for websec-lab XSS labs."""
from .bot import Bot, DEFAULT_CHROMIUM_ARGS

__all__ = ["Bot", "DEFAULT_CHROMIUM_ARGS"]
__version__ = "1.0.0"
