import os
from pathlib import Path
from dotenv import load_dotenv


_ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)


def get_bot_token() -> str:
	"""Return the Telegram bot token from environment.

	Raises:
		RuntimeError: If BOT_TOKEN is not set.
	"""
	# Read from environment (after loading .env near this file)
	token = os.getenv("BOT_TOKEN", "").strip().strip('"').strip("'")
	if not token:
		raise RuntimeError("BOT_TOKEN is not set. Please add it to .env")
	return token


