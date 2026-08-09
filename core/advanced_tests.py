#!/usr/bin/env python3
"""
Advanced testing capabilities for GraphQL AuthZ Fuzzer
Adds query testing, IDOR testing, and nested input resolution
"""

import json
import time
from typing import List, Dict, Any, Optional
import requests

class AdvancedTester:
    """Advanced testing capabilities"""
    
    def __init__(self, url: str, token: str, session: requests.Session):
        self.url = url
        self.token = token
        self.session = session
    
    def test_queries(self, schema_fields: List[Dict]) -> List[Dict]:
        """
        Test queries for data leakage with restricted token
        """
        results = []
        
        for field in schema_fields:
            query = self._build_query(field)
            if query:
                status, response = self._execute(query)
                results.append({
                    'field': field.get('name'),
                    'status': status,
                    'has_data': bool(response.get('data')),
                    'errors': response.get('errors', [])
                })
        
        return results
    
    def test_idor(self, mutation: str, args: List[Dict]) -> List[Dict]:
        """
        Test for IDOR vulnerabilities by trying different IDs
        """
        results = []
        test_ids = [1, 999, 123456, -1, 0]
        
        for test_id in test_ids:
            query = self._build_mutation_with_id(mutation, args, test_id)
            status, response = self._execute(query)
            results.append({
                'id': test_id,
                'status': status,
                'success': bool(response.get('data')),
                'errors': response.get('errors', [])
            })
        
        return results
    
    def _build_query(self, field: Dict) -> Optional[str]:
        """Build query with arguments"""
        name = field.get('name')
        args = field.get('args', [])
        
        if not args:
            return f"query {{ {name} {{ __typename }} }}"
        
        # Build with test arguments
        arg_str = ", ".join([f"{a['name']}: \"test\"" for a in args[:2]])
        return f"query {{ {name}({arg_str}) {{ __typename }} }}"
    
    def _build_mutation_with_id(self, name: str, args: List[Dict], test_id: Any) -> str:
        """Build mutation with specific ID"""
        arg_str = ", ".join([
            f"{a['name']}: {test_id}" if 'id' in a['name'].lower() 
            else f"{a['name']}: \"test\""
            for a in args
        ])
        return f"mutation {{ {name}({arg_str}) {{ __typename }} }}"
    
    def _execute(self, query: str) -> tuple:
        """Execute GraphQL query"""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        try:
            r = self.session.post(
                self.url,
                headers=headers,
                json={"query": query},
                timeout=8
            )
            return r.status_code, r.json()
        except Exception as e:
            return 500, {'errors': [{'message': str(e)}]}
