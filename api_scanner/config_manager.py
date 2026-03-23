"""
Configuration Manager for the API Vulnerability Scanner.
"""

import json
import logging
from pathlib import Path
from typing import Optional
from .models import ScanConfiguration, AuthCredentials, ValidationResult, SeverityLevel

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """Manages scan configuration loading and validation"""
    
    def load_config(self, config_path: str) -> ScanConfiguration:
        """Load and validate configuration from file"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            # Parse auth credentials if present
            auth_creds = None
            if 'auth_credentials' in config_data:
                auth_data = config_data['auth_credentials']
                auth_creds = AuthCredentials(
                    type=auth_data['type'],
                    credentials=auth_data['credentials']
                )
            
            # Parse severity threshold
            severity_threshold = SeverityLevel.INFO
            if 'severity_threshold' in config_data:
                severity_threshold = SeverityLevel(config_data['severity_threshold'])
            
            config = ScanConfiguration(
                base_url=config_data['base_url'],
                endpoints=config_data.get('endpoints'),
                excluded_endpoints=config_data.get('excluded_endpoints', []),
                security_checks=config_data.get('security_checks', []),
                custom_headers=config_data.get('custom_headers', {}),
                auth_credentials=auth_creds,
                severity_threshold=severity_threshold,
                dry_run=config_data.get('dry_run', False),
                read_only=config_data.get('read_only', True),
                request_throttle_ms=config_data.get('request_throttle_ms', 100),
                verbose_logging=config_data.get('verbose_logging', False)
            )
            
            validation = self.validate_config(config)
            if not validation.valid:
                raise ValueError(f"Invalid configuration: {', '.join(validation.errors)}")
            
            logger.info(f"Loaded configuration from {config_path}")
            return config
            
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
    
    def validate_config(self, config: ScanConfiguration) -> ValidationResult:
        """Ensure configuration is valid and safe"""
        errors = []
        
        # Validate base URL
        if not config.base_url:
            errors.append("base_url is required")
        elif not config.base_url.startswith(('http://', 'https://')):
            errors.append("base_url must start with http:// or https://")
        
        # Validate throttle
        if config.request_throttle_ms < 0:
            errors.append("request_throttle_ms must be non-negative")
        
        # Validate endpoints format
        if config.endpoints:
            for endpoint in config.endpoints:
                if not endpoint.startswith('/'):
                    errors.append(f"Endpoint must start with '/': {endpoint}")
        
        # Validate excluded endpoints format
        for endpoint in config.excluded_endpoints:
            if not endpoint.startswith('/'):
                errors.append(f"Excluded endpoint must start with '/': {endpoint}")
        
        # Warn if not using HTTPS
        if config.base_url.startswith('http://') and not config.dry_run:
            logger.warning("Using HTTP instead of HTTPS - credentials may be exposed")
        
        return ValidationResult(valid=len(errors) == 0, errors=errors)
    
    def save_config(self, config: ScanConfiguration, config_path: str) -> None:
        """Save configuration to file"""
        try:
            config_data = {
                'base_url': config.base_url,
                'endpoints': config.endpoints,
                'excluded_endpoints': config.excluded_endpoints,
                'security_checks': config.security_checks,
                'custom_headers': config.custom_headers,
                'severity_threshold': config.severity_threshold.value,
                'dry_run': config.dry_run,
                'read_only': config.read_only,
                'request_throttle_ms': config.request_throttle_ms,
                'verbose_logging': config.verbose_logging
            }
            
            if config.auth_credentials:
                config_data['auth_credentials'] = {
                    'type': config.auth_credentials.type,
                    'credentials': config.auth_credentials.credentials
                }
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Saved configuration to {config_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise
