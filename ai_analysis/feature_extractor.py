"""Extract features from parsed log events."""
import pandas as pd
from typing import List, Dict, Any

class FeatureExtractor:
    """Convert events into feature vectors."""
    
    def __init__(self, feature_columns: List[str]):
        self.feature_columns = feature_columns
    
    def extract(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Create a DataFrame of features from events."""
        df = pd.DataFrame(events)
        # Ensure all required columns exist
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = None
        
        # Encode categorical columns if needed
        df = df.fillna('')
        df['event_type_enc'] = df['event_type'].astype('category').cat.codes
        df['status_enc'] = df['status'].astype('category').cat.codes
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        df['day'] = pd.to_datetime(df['timestamp']).dt.dayofweek
        
        # Select features
        feature_df = df[['hour', 'day', 'event_type_enc', 'status_enc']]
        return feature_df