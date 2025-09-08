import os
from dotenv import load_dotenv

load_dotenv()
POSTGRES_URL = os.environ["DATABASE_URL"]