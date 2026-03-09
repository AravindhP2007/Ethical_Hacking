"""
Endpoint Discovery for the API Vulnerability Scanner.
"""

import logging
import requests
from typing import List, Optional
from urllib.parse import urljoin
from .models import Endpoint, HttpMethod, Parameter

logger = logging.getLogger(__name__)


class EndpointDiscovery:
    """Discovers API endpoints from various sources"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    def discover_from_openapi(self, spec_url: str) -> List[Endpoint]:
        """Parse OpenAPI/Swagger spec to discover endpoints"""
        try:
            logger.info(f"Fetching OpenAPI spec from {spec_url}")
            response = requests.get(spec_url, timeout=10)
            response.raise_for_status()
            spec = response.json()
            
            endpoints = []
            paths = spec.get('paths', {})
            
            for path, path_item in paths.items():
                methods = []
                parameters = []
                auth_required = False
                
                # Extract HTTP methods
                for method in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    if method in path_item:
                        methods.append(HttpMethod[method.upper()])
                        
                        # Check for authentication requirements
                        operation = path_item[method]
                        if 'security' in operation or 'security' in spec:
                            auth_required = True
                        
                        # Extract parameters
                        if 'parameters' in operation:
                            for param in operation['parameters']:
                                parameters.append(Parameter(
                                    name=param.get('name', ''),
                                    location=param.get('in', 'query'),
                                    type=param.get('schema', {}).get('type', 'string'),
                                    required=param.get('required', False)
                                ))
                
                if methods:
                    endpoint = Endpoint(
                        path=path,
                        methods=methods,
                        parameters=parameters,
                        authentication_required=auth_required
                    )
                    endpoints.append(endpoint)
                    logger.debug(f"Discovered endpoint: {path} with methods {[m.value for m in methods]}")
            
            logger.info(f"Discovered {len(endpoints)} endpoints from OpenAPI spec")
            return endpoints
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch OpenAPI spec: {e}")
            return []
        except (KeyError, ValueError) as e:
            logger.error(f"Failed to parse OpenAPI spec: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during OpenAPI discovery: {e}")
            return []
    
    def discover_from_manual(self, endpoints: List[str]) -> List[Endpoint]:
        """Build endpoint list from manual configuration"""
        discovered = []
        
        for endpoint_path in endpoints:
            # Probe for supported methods
            methods = self.probe_http_methods(endpoint_path)
            
            if methods:
                endpoint = Endpoint(
                    path=endpoint_path,
                    methods=methods,
                    parameters=[],
                    authentication_required=False  # Will be detected during testing
                )
                discovered.append(endpoint)
                logger.debug(f"Manually configured endpoint: {endpoint_path}")
        
        logger.info(f"Configured {len(discovered)} endpoints manually")
        return discovered
    
    def probe_http_methods(self, endpoint_path: str) -> List[HttpMethod]:
        """Determine supported HTTP methods for endpoint"""
        url = urljoin(self.base_url, endpoint_path)
        supported_methods = []
        
        try:
            # Try OPTIONS request first
            response = requests.options(url, timeout=5)
            if 'Allow' in response.headers:
                allowed = response.headers['Allow'].split(',')
                for method in allowed:
                    method = method.strip().upper()
                    try:
                        supported_methods.append(HttpMethod[method])
                    except KeyError:
                        pass
                
                if supported_methods:
                    logger.debug(f"Probed methods for {endpoint_path}: {[m.value for m in supported_methods]}")
                    return supported_methods
        
        except requests.RequestException:
            pass
        
        # Fallback: try common methods
        common_methods = [HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE]
        for method in common_methods:
            try:
                response = requests.request(
                    method.value,
                    url,
                    timeout=5,
                    allow_redirects=False
                )
                # If we don't get 405 (Method Not Allowed), the method is likely supported
                if response.status_code != 405:
                    supported_methods.append(method)
            except requests.RequestException:
                pass
        
        if not supported_methods:
            # Default to GET if nothing else works
            supported_methods = [HttpMethod.GET]
        
        logger.debug(f"Probed methods for {endpoint_path}: {[m.value for m in supported_methods]}")
        return supported_methods
