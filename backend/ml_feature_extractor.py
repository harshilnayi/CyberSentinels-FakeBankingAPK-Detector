# =====================================================================
# CYBERSENTINELS ML FEATURE EXTRACTOR - PHASE 1
# Advanced Feature Engineering for Banking APK Detection
# Integrates with existing advanced_detection_logic.py system
# =====================================================================

import numpy as np
import pandas as pd
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberSentinelsFeatureExtractor:
    """
    Advanced feature extractor for CyberSentinels Banking APK Detection
    Converts analysis results into ML-ready feature vectors
    """
    
    def __init__(self):
        self.feature_names = []
        self.feature_categories = {
            'file_features': [],
            'permission_features': [], 
            'behavioral_features': [],
            'static_features': [],
            'banking_features': [],
            'certificate_features': [],
            'string_features': [],
            'logo_features': [],
            'network_features': [],
            'advanced_features': []
        }
        self._initialize_feature_names()
        
    def _initialize_feature_names(self):
        """Initialize comprehensive feature set names"""
        
        # FILE-BASED FEATURES (10 features)
        file_features = [
            'file_size_normalized',      # Normalized file size (0-1)
            'file_size_category',        # Size category (0=small, 1=medium, 2=large, 3=huge)
            'apk_compression_ratio',     # Compression ratio indicator
            'file_entropy',              # File entropy (randomness indicator)
            'dex_files_count',           # Number of DEX files
            'native_libraries_count',    # Number of .so files
            'resources_count',           # Number of resource files
            'assets_count',              # Number of asset files
            'certificates_count',        # Number of certificates
            'manifest_complexity'        # AndroidManifest.xml complexity
        ]
        
        # PERMISSION-BASED FEATURES (15 features)
        permission_features = [
            'total_permissions',         # Total number of permissions
            'dangerous_permissions',     # Number of dangerous permissions
            'normal_permissions',        # Number of normal permissions
            'signature_permissions',     # Number of signature permissions
            'permission_density',        # Dangerous/Total ratio
            'banking_permissions',       # Banking-related permissions
            'sms_permissions',          # SMS-related permissions  
            'phone_permissions',        # Phone-related permissions
            'location_permissions',     # Location permissions
            'camera_permissions',       # Camera permissions
            'microphone_permissions',   # Microphone permissions
            'overlay_permissions',      # System overlay permissions
            'admin_permissions',        # Device admin permissions
            'accessibility_permissions', # Accessibility permissions
            'banking_trojan_pattern'    # Banking trojan permission pattern (0/1)
        ]
        
        # BEHAVIORAL ANALYSIS FEATURES (12 features)
        behavioral_features = [
            'banking_trojan_score',     # Your existing banking trojan score
            'overlay_detection',        # Overlay attack detection (0/1)
            'sms_interception',        # SMS interception capability (0/1)
            'keylogging_detected',     # Keylogging patterns (0/1)
            'screen_recording',        # Screen recording capability (0/1)
            'accessibility_abuse',     # Accessibility service abuse (0/1)
            'bluetooth_abuse',         # Bluetooth exploitation (0/1)
            'camera_abuse',           # Camera abuse detection (0/1)
            'microphone_abuse',       # Microphone abuse (0/1)
            'suspicious_behaviors_count', # Total suspicious behaviors
            'behavioral_confidence',   # Confidence in behavioral analysis
            'anti_analysis_score'     # Anti-analysis techniques score
        ]
        
        # STATIC ANALYSIS FEATURES (8 features)
        static_features = [
            'activities_count',        # Number of activities
            'services_count',         # Number of services
            'receivers_count',        # Number of receivers
            'providers_count',        # Number of content providers
            'component_density',      # Components per permission ratio
            'exported_components',    # Number of exported components
            'intent_filters_count',   # Number of intent filters
            'api_calls_count'        # Estimated API calls count
        ]
        
        # BANKING-SPECIFIC FEATURES (8 features) - YOUR COMPETITIVE ADVANTAGE
        banking_features = [
            'impersonation_score',           # Your Indian banking impersonation score
            'logo_similarity_score',         # Logo similarity (0-1)  
            'logo_match_detected',           # Logo match boolean (0/1)
            'legitimate_bank_similarity',    # Similarity to legitimate banks
            'banking_keywords_count',        # Banking keywords in strings
            'financial_api_usage',          # Financial API usage indicators
            'package_name_suspicious',      # Suspicious package name (0/1)
            'app_name_impersonation'        # App name impersonation score
        ]
        
        # CERTIFICATE ANALYSIS FEATURES (6 features)
        certificate_features = [
            'certificate_signed',       # Is APK signed (0/1)
            'certificate_suspicious',   # Suspicious certificate (0/1)
            'self_signed_cert',        # Self-signed certificate (0/1)
            'cert_validity_period',    # Certificate validity in days
            'cert_key_length',         # Certificate key length
            'cert_algorithm_strength'  # Certificate algorithm strength
        ]
        
        # STRING ANALYSIS FEATURES (6 features)
        string_features = [
            'suspicious_strings_count',  # Count of suspicious strings
            'urls_count',               # Number of URLs found
            'ip_addresses_count',       # Number of IP addresses
            'suspicious_domains',       # Suspicious domains count
            'hardcoded_secrets',       # Hardcoded secrets/keys count  
            'encryption_indicators'    # Encryption usage indicators
        ]
        
        # LOGO ANALYSIS FEATURES (5 features) - UNIQUE COMPETITIVE ADVANTAGE
        logo_features = [
            'logo_extracted',          # Logo successfully extracted (0/1)
            'logo_phash_similarity',   # Perceptual hash similarity score
            'logo_bank_match',         # Matches known bank logo (0/1)
            'logo_visual_complexity',  # Logo visual complexity score
            'logo_brand_confidence'    # Confidence in brand matching
        ]
        
        # NETWORK ANALYSIS FEATURES (4 features)
        network_features = [
            'network_permissions',     # Network-related permissions
            'suspicious_network_calls', # Suspicious network behavior
            'ssl_pinning_bypassed',    # SSL pinning bypass detected
            'c2_communication_pattern' # Command & Control patterns
        ]
        
        # ADVANCED DETECTION FEATURES (6 features)
        advanced_features = [
            'obfuscation_detected',    # Code obfuscation (0/1)
            'packing_detected',       # Binary packing (0/1)
            'dynamic_loading',        # Dynamic code loading (0/1)
            'root_detection_evasion', # Root detection evasion
            'emulator_detection',     # Emulator detection code
            'virustotal_detection_ratio' # VirusTotal detection ratio
        ]
        
        # Store all features
        self.feature_categories['file_features'] = file_features
        self.feature_categories['permission_features'] = permission_features
        self.feature_categories['behavioral_features'] = behavioral_features
        self.feature_categories['static_features'] = static_features  
        self.feature_categories['banking_features'] = banking_features
        self.feature_categories['certificate_features'] = certificate_features
        self.feature_categories['string_features'] = string_features
        self.feature_categories['logo_features'] = logo_features
        self.feature_categories['network_features'] = network_features
        self.feature_categories['advanced_features'] = advanced_features
        
        # Create master feature list
        self.feature_names = []
        for category_features in self.feature_categories.values():
            self.feature_names.extend(category_features)
            
        logger.info(f"✅ Initialized {len(self.feature_names)} features across {len(self.feature_categories)} categories")
        
    def extract_features_from_analysis(self, analysis_results: Dict) -> np.ndarray:
        """
        Extract ML-ready feature vector from your existing analysis results
        
        Args:
            analysis_results: Output from advanced_detection_logic.py analyze_apk_comprehensive()
            
        Returns:
            numpy array of feature values
        """
        try:
            features = np.zeros(len(self.feature_names))
            feature_idx = 0
            
            # 1. FILE FEATURES (10 features)
            file_info = analysis_results.get('file_info', {})
            
            # File size normalization (0-1 range)
            file_size = file_info.get('size', 0)
            features[feature_idx] = min(file_size / 100_000_000, 1.0)  # Normalize to 100MB max
            feature_idx += 1
            
            # File size category
            if file_size < 1_000_000:      # < 1MB
                features[feature_idx] = 0
            elif file_size < 10_000_000:   # < 10MB  
                features[feature_idx] = 1
            elif file_size < 50_000_000:   # < 50MB
                features[feature_idx] = 2
            else:                          # >= 50MB
                features[feature_idx] = 3
            feature_idx += 1
            
            # APK compression, entropy, file counts (simplified for now)
            features[feature_idx:feature_idx+7] = [0.5, 0.7, 1, 0, 10, 5, 1]  # Default values
            feature_idx += 7
            
            # 2. PERMISSION FEATURES (15 features)
            perm_analysis = analysis_results.get('permission_analysis', {})
            
            features[feature_idx] = perm_analysis.get('total_permissions', 0)
            feature_idx += 1
            
            dangerous_perms = len(perm_analysis.get('dangerous_permissions', []))
            features[feature_idx] = dangerous_perms
            feature_idx += 1
            
            total_perms = features[feature_idx-2]
            features[feature_idx] = max(0, total_perms - dangerous_perms)  # Normal permissions
            feature_idx += 1
            
            features[feature_idx] = 0  # Signature permissions (placeholder)
            feature_idx += 1
            
            # Permission density
            features[feature_idx] = dangerous_perms / max(total_perms, 1)
            feature_idx += 1
            
            # Count specific permission types
            all_permissions = perm_analysis.get('all_permissions', [])
            banking_perm_keywords = ['account', 'bank', 'financial', 'payment']
            sms_perm_keywords = ['sms', 'message']
            phone_perm_keywords = ['phone', 'call']
            
            features[feature_idx] = sum(1 for perm in all_permissions if any(kw in perm.lower() for kw in banking_perm_keywords))
            feature_idx += 1
            features[feature_idx] = sum(1 for perm in all_permissions if any(kw in perm.lower() for kw in sms_perm_keywords))
            feature_idx += 1  
            features[feature_idx] = sum(1 for perm in all_permissions if any(kw in perm.lower() for kw in phone_perm_keywords))
            feature_idx += 1
            
            # Location, camera, microphone, overlay, admin, accessibility permissions
            location_perms = sum(1 for perm in all_permissions if 'location' in perm.lower())
            camera_perms = sum(1 for perm in all_permissions if 'camera' in perm.lower())
            mic_perms = sum(1 for perm in all_permissions if 'record_audio' in perm.lower())
            overlay_perms = sum(1 for perm in all_permissions if 'system_alert_window' in perm.lower())
            admin_perms = sum(1 for perm in all_permissions if 'device_admin' in perm.lower())
            access_perms = sum(1 for perm in all_permissions if 'accessibility' in perm.lower())
            
            features[feature_idx:feature_idx+6] = [location_perms, camera_perms, mic_perms, overlay_perms, admin_perms, access_perms]
            feature_idx += 6
            
            # Banking trojan pattern detection
            suspicious_combos = perm_analysis.get('suspicious_combinations', [])
            features[feature_idx] = 1 if 'banking_trojan_pattern' in suspicious_combos else 0
            feature_idx += 1
            
            # 3. BEHAVIORAL FEATURES (12 features)
            behavioral = analysis_results.get('behavioral_indicators', {})
            
            features[feature_idx] = behavioral.get('banking_trojan_score', 0) / 100.0  # Normalize to 0-1
            feature_idx += 1
            
            # Boolean behavioral indicators
            behavioral_bools = [
                behavioral.get('overlay_detection', False),
                behavioral.get('sms_interception', False), 
                behavioral.get('keylogging_detected', False),
                behavioral.get('screen_recording', False),
                behavioral.get('accessibility_abuse', False),
                behavioral.get('bluetooth_abuse', False),
                behavioral.get('camera_abuse', False),
                behavioral.get('microphone_abuse', False)
            ]
            
            features[feature_idx:feature_idx+8] = [int(b) for b in behavioral_bools]
            feature_idx += 8
            
            # Suspicious behaviors count
            features[feature_idx] = len(behavioral.get('suspicious_behaviors', []))
            feature_idx += 1
            
            # Behavioral confidence and anti-analysis score
            features[feature_idx] = 0.8  # Default confidence
            feature_idx += 1
            
            anti_analysis = analysis_results.get('anti_analysis_detection', {})
            anti_score = sum([
                anti_analysis.get('obfuscation_detected', False),
                anti_analysis.get('packing_detected', False),
                anti_analysis.get('root_detection', False),
                anti_analysis.get('debugger_detection', False)
            ])
            features[feature_idx] = anti_score / 4.0  # Normalize to 0-1
            feature_idx += 1
            
            # 4. STATIC ANALYSIS FEATURES (8 features)
            static_analysis = analysis_results.get('static_analysis', {})
            manifest = static_analysis.get('manifest_analysis', {})
            
            activities = manifest.get('activities_count', 1)
            services = manifest.get('services_count', 0) 
            receivers = manifest.get('receivers_count', 0)
            providers = 0  # Placeholder
            
            features[feature_idx:feature_idx+4] = [activities, services, receivers, providers]
            feature_idx += 4
            
            # Component density
            features[feature_idx] = (activities + services + receivers) / max(total_perms, 1)
            feature_idx += 1
            
            # Exported components, intent filters, API calls (placeholders)
            features[feature_idx:feature_idx+3] = [2, 5, 50]
            feature_idx += 3
            
            # 5. BANKING FEATURES (8 features) - YOUR COMPETITIVE ADVANTAGE
            indian_banking = analysis_results.get('indian_banking_check', {})
            logo_analysis = analysis_results.get('logo_analysis', {})
            
            features[feature_idx] = indian_banking.get('impersonation_score', 0) / 100.0
            feature_idx += 1
            
            features[feature_idx] = logo_analysis.get('similarity', 0)
            feature_idx += 1
            
            features[feature_idx] = int(logo_analysis.get('match', False))
            feature_idx += 1
            
            # Legitimate bank similarity, banking keywords, financial API usage
            package_name = indian_banking.get('package_name', '').lower()
            legitimate_similarity = 0
            for legit_package in ['com.sbi', 'com.icici', 'com.hdfc', 'com.axis', 'com.paytm']:
                if legit_package in package_name:
                    legitimate_similarity = 0.8
                    break
                    
            features[feature_idx] = legitimate_similarity
            feature_idx += 1
            
            string_analysis = analysis_results.get('string_analysis', {})
            banking_keywords = sum(1 for s in string_analysis.get('suspicious_strings', []) 
                                 if any(kw in s.lower() for kw in ['bank', 'credit', 'debit', 'payment', 'account']))
            features[feature_idx] = banking_keywords
            feature_idx += 1
            
            features[feature_idx] = 0  # Financial API usage (placeholder)
            feature_idx += 1
            
            # Package name suspicious
            suspicious_keywords = ['fake', 'malware', 'test', 'trojan']
            features[feature_idx] = int(any(kw in package_name for kw in suspicious_keywords))
            feature_idx += 1
            
            # App name impersonation
            app_name = indian_banking.get('app_name', '').lower()
            features[feature_idx] = indian_banking.get('impersonation_score', 0) / 100.0
            feature_idx += 1
            
            # 6. CERTIFICATE FEATURES (6 features)
            cert_analysis = analysis_results.get('certificate_analysis', {})
            
            features[feature_idx] = int(cert_analysis.get('is_signed', False))
            feature_idx += 1
            
            features[feature_idx] = int(cert_analysis.get('certificate_suspicious', False))
            feature_idx += 1
            
            # Self-signed detection
            cert_info = cert_analysis.get('certificate_info', {})
            subject = cert_info.get('subject', '')
            issuer = cert_info.get('issuer', '')
            features[feature_idx] = int(subject == issuer and subject != '')
            feature_idx += 1
            
            # Certificate validity, key length, algorithm strength (placeholders)
            features[feature_idx:feature_idx+3] = [365, 2048, 0.8]
            feature_idx += 3
            
            # 7. STRING ANALYSIS FEATURES (6 features)
            features[feature_idx] = len(string_analysis.get('suspicious_strings', []))
            feature_idx += 1
            
            features[feature_idx] = len(string_analysis.get('urls_found', []))
            feature_idx += 1
            
            features[feature_idx] = len(string_analysis.get('ip_addresses', []))
            feature_idx += 1
            
            # Suspicious domains, hardcoded secrets, encryption indicators (placeholders)
            features[feature_idx:feature_idx+3] = [0, 0, 1]
            feature_idx += 3
            
            # 8. LOGO FEATURES (5 features) - UNIQUE ADVANTAGE
            features[feature_idx] = int('logo_analysis' in analysis_results)
            feature_idx += 1
            
            features[feature_idx] = logo_analysis.get('similarity', 0)
            feature_idx += 1
            
            features[feature_idx] = int(logo_analysis.get('match', False))
            feature_idx += 1
            
            # Logo complexity and brand confidence (placeholders)
            features[feature_idx:feature_idx+2] = [0.5, logo_analysis.get('similarity', 0)]
            feature_idx += 2
            
            # 9. NETWORK FEATURES (4 features)
            network_analysis = analysis_results.get('network_analysis', {})
            features[feature_idx] = len(network_analysis.get('network_permissions', []))
            feature_idx += 1
            
            features[feature_idx:feature_idx+3] = [0, 0, 0]  # Placeholders
            feature_idx += 3
            
            # 10. ADVANCED FEATURES (6 features)
            features[feature_idx] = int(anti_analysis.get('obfuscation_detected', False))
            feature_idx += 1
            
            features[feature_idx] = int(anti_analysis.get('packing_detected', False))
            feature_idx += 1
            
            features[feature_idx:feature_idx+2] = [0, 0]  # Dynamic loading, root evasion placeholders
            feature_idx += 2
            
            features[feature_idx] = int(anti_analysis.get('emulator_detection', False))
            feature_idx += 1
            
            # VirusTotal detection ratio
            vt_results = analysis_results.get('virustotal_scan', {})
            if vt_results and 'positives' in vt_results and 'total' in vt_results:
                features[feature_idx] = vt_results['positives'] / max(vt_results['total'], 1)
            else:
                features[feature_idx] = 0
            feature_idx += 1
            
            logger.info(f"✅ Extracted {len(features)} features successfully")
            return features
            
        except Exception as e:
            logger.error(f"❌ Feature extraction failed: {e}")
            return np.zeros(len(self.feature_names))
    
    def create_feature_dataframe(self, feature_vectors: List[np.ndarray], labels: List[int] = None) -> pd.DataFrame:
        """
        Create pandas DataFrame from feature vectors
        
        Args:
            feature_vectors: List of feature vectors
            labels: List of labels (0=benign, 1=malware)
            
        Returns:
            pandas DataFrame with features and labels
        """
        try:
            # Create DataFrame from feature vectors
            df = pd.DataFrame(feature_vectors, columns=self.feature_names)
            
            # Add labels if provided
            if labels:
                df['label'] = labels
                df['is_malware'] = labels  # Boolean version
            
            logger.info(f"✅ Created DataFrame with {len(df)} samples and {len(self.feature_names)} features")
            return df
            
        except Exception as e:
            logger.error(f"❌ DataFrame creation failed: {e}")
            return pd.DataFrame()
    
    def get_feature_info(self) -> Dict:
        """Get comprehensive information about features"""
        return {
            'total_features': len(self.feature_names),
            'feature_categories': {cat: len(features) for cat, features in self.feature_categories.items()},
            'feature_names': self.feature_names,
            'categories': self.feature_categories
        }
    
    def save_feature_importance(self, feature_importance: np.ndarray, output_path: str):
        """Save feature importance analysis"""
        try:
            importance_data = []
            for i, importance in enumerate(feature_importance):
                # Determine category
                category = 'unknown'
                cumulative_idx = 0
                for cat, features in self.feature_categories.items():
                    if cumulative_idx <= i < cumulative_idx + len(features):
                        category = cat
                        break
                    cumulative_idx += len(features)
                
                importance_data.append({
                    'feature_name': self.feature_names[i],
                    'importance': importance,
                    'category': category,
                    'rank': i + 1
                })
            
            # Sort by importance
            importance_data.sort(key=lambda x: x['importance'], reverse=True)
            
            # Save to file
            importance_df = pd.DataFrame(importance_data)
            importance_df.to_csv(output_path, index=False)
            
            logger.info(f"✅ Feature importance saved to {output_path}")
            return importance_df
            
        except Exception as e:
            logger.error(f"❌ Feature importance save failed: {e}")
            return None

if __name__ == "__main__":
    # Test the feature extractor
    extractor = CyberSentinelsFeatureExtractor()
    
    # Print feature information
    info = extractor.get_feature_info()
    print("=== CYBERSENTINELS ML FEATURE EXTRACTOR ===")
    print(f"Total Features: {info['total_features']}")
    print("\nFeature Categories:")
    for category, count in info['feature_categories'].items():
        print(f"  {category}: {count} features")
    
    # Test with dummy analysis results
    dummy_results = {
        'file_info': {'size': 15000000, 'sha256': 'test_hash'},
        'permission_analysis': {
            'total_permissions': 25,
            'dangerous_permissions': ['android.permission.READ_SMS', 'android.permission.SYSTEM_ALERT_WINDOW'],
            'all_permissions': ['android.permission.INTERNET', 'android.permission.READ_SMS'],
            'suspicious_combinations': ['banking_trojan_pattern']
        },
        'behavioral_indicators': {
            'banking_trojan_score': 75,
            'overlay_detection': True,
            'sms_interception': True,
            'keylogging_detected': False
        },
        'indian_banking_check': {
            'impersonation_score': 80,
            'package_name': 'com.fake.sbi.app'
        },
        'logo_analysis': {
            'match': True,
            'similarity': 0.85,
            'bank': 'SBI'
        }
    }
    
    # Extract features
    features = extractor.extract_features_from_analysis(dummy_results)
    print(f"\n✅ Successfully extracted feature vector of length {len(features)}")
    print(f"Sample feature values: {features[:10]}")