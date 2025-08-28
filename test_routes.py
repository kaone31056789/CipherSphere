"""
Quick test to verify download routes are properly registered
"""

import sys
import os
sys.path.append('.')

from app import app

def test_routes():
    print("Checking if download routes are registered...")
    print("=" * 50)
    
    with app.app_context():
        # Get all routes
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'rule': rule.rule
            })
        
        # Look for download-related routes
        download_routes = [r for r in routes if 'download' in r['endpoint'] or 'download' in r['rule']]
        
        print("Download-related routes found:")
        for route in download_routes:
            print(f"✅ {route['endpoint']}: {route['rule']} {route['methods']}")
        
        # Check specific routes we added
        expected_routes = [
            'download_encrypted_file',
            'download_encrypted_temp', 
            'download_decrypted',
            'download_file'
        ]
        
        print(f"\nChecking expected routes:")
        for expected in expected_routes:
            found = any(r['endpoint'] == expected for r in routes)
            status = "✅" if found else "❌"
            print(f"{status} {expected}")
        
        print("=" * 50)
        print("Route check completed!")

if __name__ == "__main__":
    test_routes()
