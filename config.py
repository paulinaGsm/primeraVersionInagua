import os

class Config:
    MYSQL_HOST = os.getenv("MYSQL_HOST", "bblvor78azrcodwiyzg1-mysql.services.clever-cloud.com")
    MYSQL_USER = os.getenv("MYSQL_USER", "u7x4huf4ciefuwwv")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "SM7OzX8vAStcmW3YDCVY")
    MYSQL_DB = os.getenv("MYSQL_DB", "bblvor78azrcodwiyzg1")
    MYSQL_CURSORCLASS = "DictCursor"
