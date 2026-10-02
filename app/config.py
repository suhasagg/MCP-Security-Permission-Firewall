from pydantic_settings import BaseSettings,SettingsConfigDict
class Settings(BaseSettings):
    env:str="dev"
    database_url:str="postgresql+asyncpg://firewall:firewall@localhost:5432/firewall"
    redis_url:str="redis://localhost:6379/0"
    jwt_secret:str="change-me"
    jwt_algorithm:str="HS256"
    approval_signing_secret:str="change-me"
    mcp_timeout_seconds:float=20
    max_output_bytes:int=262144
    model_config=SettingsConfigDict(env_file=".env",extra="ignore")
settings=Settings()
