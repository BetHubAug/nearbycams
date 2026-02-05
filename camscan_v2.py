import os
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Error Hierarchy
class BaseError(Exception):
    """Base class for other exceptions."""
    pass

class ConfigError(BaseError):
    """Raised when there is a configuration error."""
    pass

class ResourceError(BaseError):
    """Raised for errors related to resource management."""
    pass

# Environment-Based Configuration
class Config:
    def __init__(self):
        self.environment = os.getenv('APP_ENV', 'development')
        self.api_endpoint = os.getenv('API_ENDPOINT', 'http://localhost:5000')

    def validate(self):
        if not self.api_endpoint:
            raise ConfigError("API endpoint is not configured.")

# Multi-Source Discovery Logic
class ResourceDiscovery:
    def __init__(self, config):
        self.config = config
    
    def discover(self):
        logger.info("Discovering resources...")
        # Logic for multi-source discovery goes here
        # Example discovery
        return [{"name": "Camera1"}, {"name": "Camera2"}]

@contextmanager
def resource_cleanup():
    logger.info("Acquiring resources...")
    try:
        yield
    finally:
        logger.info("Cleaning up resources...")


def main():
    config = Config()
    config.validate()

    with resource_cleanup():
        discovery = ResourceDiscovery(config)
        resources = discovery.discover()
        logger.info(f"Discovered resources: {resources}")

if __name__ == "__main__":
    main()