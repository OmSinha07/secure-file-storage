import json
import os

class KeyStorage:
    """Simple key storage (use database in production)"""
    
    def __init__(self, storage_file='user_keys.json'):
        self.storage_file = storage_file
        self.keys = self.load_keys()
    
    def load_keys(self):
        """Load keys from file"""
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_keys(self):
        """Save keys to file"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def get_user_keys(self, user_id='default_user'):
        """Get user's key pair"""
        return self.keys.get(user_id, {})
    
    def store_user_keys(self, public_key, private_key, user_id='default_user'):
        """Store user's key pair"""
        self.keys[user_id] = {
            'public_key': public_key,
            'private_key': private_key
        }
        self.save_keys()
    
    def has_user_keys(self, user_id='default_user'):
        """Check if user has keys"""
        return user_id in self.keys

# Global instance
key_storage = KeyStorage()