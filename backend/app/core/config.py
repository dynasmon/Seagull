import os


class Settings:
    NETWATCH_REDIS_HOST: str = os.getenv("NETWATCH_REDIS_HOST", "redis")
    NETWATCH_REDIS_PORT: int = int(os.getenv("NETWATCH_REDIS_PORT", "6379"))

    # Optional full SQLAlchemy DSN (preferred). Example:
    #   postgresql+psycopg2://user:pass@postgres:5432/netwatch
    DB_URL: str | None = os.getenv("NETWATCH_DB_URL")

    DB_HOST: str = os.getenv("NETWATCH_DB_HOST", "postgres")
    DB_PORT: int = int(os.getenv("NETWATCH_DB_PORT", "5432"))
    DB_NAME: str = os.getenv("NETWATCH_DB_NAME", "netwatch")
    DB_USER: str = os.getenv("NETWATCH_DB_USER", "netwatch")
    DB_PASSWORD: str = os.getenv("NETWATCH_DB_PASSWORD", "netwatch123")

    @property
    def database_url(self) -> str:
        if self.DB_URL:
            return self.DB_URL

        return (
            f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )


settings = Settings()
