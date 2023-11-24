import os
from pathlib import Path

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ilyes:ilyes@localhost/carved_rock")

    # Add other configuration settings 
