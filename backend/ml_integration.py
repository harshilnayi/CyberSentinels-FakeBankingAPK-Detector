# =====================================================================
# CYBERSENTINELS ML INTEGRATION - PHASE 3
# Integrates ML Models with Existing Advanced Detection System
# Hybrid approach combining rule-based + ML predictions
# =====================================================================

import numpy as np
import pandas as pd
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path

# Import your existing components
try:
    from ml_feature_extractor import CyberSentinelsFeatureExtractor
    from ml_models import CyberSentinelsMLClassifier
except ImportError as e:
    logging.warning(f"ML components not found: {e}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HybridAPKDetector:
    """
    Hybrid APK Detector combining rule-based analysis with ML predictions
    Integrates with your existing advanced_detection_logic.py system
    """
    
    def __init__(self, ml_model_path: str = "trained_models"):
        self.feature_extractor = CyberSentinelsFeatureExtractor()
        self.ml_classifier = CyberSentinelsMLClassifier(ml_model_path)
        self.ml_enabled = False
        
        # Hybrid scoring weights
        self.weights = {
            'rule_based_score': 0.6,      # Your existing rule-based analysis
            'ml_ensemble_score': 0.4,     # ML ensemble prediction
            'confidence_threshold': 0.7,   # Minimum confidence for ML
            'consensus_threshold': 0.8     # Threshold for high confidence
        }
        
        # Load pre-trained models if available
        self._initialize_ml_models()
        
    def _initialize_ml_models(self):
        """Initialize and load ML models"""
        try:
            if self.ml_classifier.load_models():
                self.ml_enabled = True
                logger.info("✅ ML models loaded successfully - Hybrid mode enabled")
            else:
                logger.warning("⚠️ ML models not found - Using rule-based mode only")
                
        except Exception as e:
            logger.error(f"❌ ML model initialization failed: {e}")
            logger.info("📝 Using rule-based detection only")
    
    def analyze_apk_hybrid(self, apk_path: str, existing_analysis: Dict = None) -> Dict[str, Any]:
        """
        Perform hybrid analysis combining your existing system with ML
        
        Args:
            apk_path: Path to APK file
            existing_analysis: Your existing analysis results from advanced_detection_logic.py
            
        Returns:
            Enhanced analysis results with ML predictions
        """
        try:
            logger.info(f"🔬 Starting hybrid analysis for {os.path.basename(apk_path)}")
            
            # If no existing analysis provided, we'll work with what we have
            if existing_analysis is None:
                existing_analysis = {}
                logger.warning("⚠️ No existing analysis provided - using minimal analysis")
            
            # Extract features for ML
            feature_vector = self.feature_extractor.extract_features_from_analysis(existing_analysis)
            
            # Get rule-based risk assessment
            rule_based_assessment = existing_analysis.get('risk_assessment', {})
            rule_based_score = rule_based_assessment.get('overall_score', 0) / 100.0  # Normalize to 0-1
            rule_based_risk_level = rule_based_assessment.get('risk_level', 'UNKNOWN')
            
            # Initialize hybrid results with existing analysis
            hybrid_results = existing_analysis.copy()
            
            # Add ML predictions if available
            if self.ml_enabled and len(feature_vector) > 0:
                ml_predictions = self.ml_classifier.predict_single(feature_vector, use_ensemble=True)
                
                # Calculate hybrid score
                hybrid_score, confidence_level = self._calculate_hybrid_score(
                    rule_based_score, ml_predictions, rule_based_risk_level
                )
                
                # Enhanced risk assessment
                enhanced_risk_assessment = self._create_enhanced_risk_assessment(
                    rule_based_assessment, ml_predictions, hybrid_score, confidence_level
                )
                
                # Update results with ML enhancements
                hybrid_results.update({
                    'ml_analysis': {
                        'enabled': True,
                        'feature_vector_length': len(feature_vector),
                        'predictions': ml_predictions,
                        'feature_extraction_success': True
                    },
                    'hybrid_assessment': {
                        'hybrid_score': hybrid_score * 100,  # Convert back to 0-100 scale
                        'confidence_level': confidence_level,
                        'rule_based_weight': self.weights['rule_based_score'],
                        'ml_weight': self.weights['ml_ensemble_score'],
                        'consensus_achieved': confidence_level == 'HIGH'
                    },
                    'risk_assessment': enhanced_risk_assessment  # Override with enhanced version
                })
                
                logger.info(f"🎯 Hybrid analysis complete - Score: {hybrid_score*100:.1f}, Confidence: {confidence_level}")
                
            else:
                # ML not available - use rule-based only
                hybrid_results.update({
                    'ml_analysis': {
                        'enabled': False,
                        'reason': 'ML models not loaded' if not self.ml_enabled else 'Feature extraction failed',
                        'feature_extraction_success': len(feature_vector) > 0
                    },
                    'hybrid_assessment': {
                        'hybrid_score': rule_based_score * 100,
                        'confidence_level': 'RULE_BASED_ONLY',
                        'rule_based_weight': 1.0,
                        'ml_weight': 0.0,
                        'consensus_achieved': False
                    }
                })
                
                logger.info("📋 Using rule-based analysis only")
            
            # Add hybrid metadata
            hybrid_results['analysis_type'] = 'hybrid' if self.ml_enabled else 'rule_based'
            hybrid_results['analysis_timestamp'] = datetime.now().isoformat()
            hybrid_results['analyzer_version'] = 'CyberSentinels-Hybrid-v1.0'
            
            return hybrid_results
            
        except Exception as e:
            logger.error(f"❌ Hybrid analysis failed: {e}")
            # Fallback to existing analysis
            return existing_analysis if existing_analysis else {'error': str(e)}
    
    def _calculate_hybrid_score(self, rule_score: float, ml_predictions: Dict, 
                               rule_risk_level: str) -> Tuple[float, str]:
        """
        Calculate hybrid score combining rule-based and ML predictions
        
        Returns:
            Tuple of (hybrid_score, confidence_level)
        """
        try:
            # Get ML ensemble prediction
            if 'ensemble' in ml_predictions:
                ml_score = ml_predictions['ensemble']['malware_probability']
                ml_confidence = ml_predictions['ensemble']['confidence']
            else:
                # Fallback to Random Forest if ensemble not available
                if 'random_forest' in ml_predictions:
                    ml_score = ml_predictions['random_forest']['malware_probability']
                    ml_confidence = ml_predictions['random_forest']['confidence']
                else:
                    # No ML prediction available
                    return rule_score, 'LOW'
            
            # Calculate weighted hybrid score
            hybrid_score = (
                self.weights['rule_based_score'] * rule_score +
                self.weights['ml_ensemble_score'] * ml_score
            )
            
            # Determine confidence level
            if ml_confidence >= self.weights['consensus_threshold']:
                # High confidence - both systems agree
                if abs(rule_score - ml_score) < 0.2:  # Agreement within 20%
                    confidence_level = 'HIGH'
                else:
                    confidence_level = 'MEDIUM'
            elif ml_confidence >= self.weights['confidence_threshold']:
                confidence_level = 'MEDIUM'
            else:
                confidence_level = 'LOW'
            
            # Boost confidence for critical cases
            if rule_risk_level in ['HIGH', 'CRITICAL'] and ml_score > 0.7:
                confidence_level = 'HIGH'
            
            return hybrid_score, confidence_level
            
        except Exception as e:
            logger.error(f"❌ Hybrid score calculation failed: {e}")
            return rule_score, 'LOW'
    
    def _create_enhanced_risk_assessment(self, rule_assessment: Dict, ml_predictions: Dict,
                                       hybrid_score: float, confidence_level: str) -> Dict[str, Any]:
        """Create enhanced risk assessment combining rule-based and ML insights"""
        
        # Start with existing rule-based assessment
        enhanced_assessment = rule_assessment.copy()
        
        # Update with hybrid score
        enhanced_assessment['overall_score'] = int(hybrid_score * 100)
        
        # Determine risk level based on hybrid score
        if hybrid_score >= 0.8:
            enhanced_assessment['risk_level'] = 'CRITICAL'
            enhanced_assessment['recommendation'] = 'BLOCK IMMEDIATELY - Critical threat confirmed by both rule-based and ML analysis'
        elif hybrid_score >= 0.65:
            enhanced_assessment['risk_level'] = 'HIGH' 
            enhanced_assessment['recommendation'] = 'BLOCK - High risk confirmed by hybrid analysis'
        elif hybrid_score >= 0.5:
            enhanced_assessment['risk_level'] = 'MEDIUM'
            enhanced_assessment['recommendation'] = 'CAUTION - Medium risk detected by hybrid analysis'
        elif hybrid_score >= 0.25:
            enhanced_assessment['risk_level'] = 'LOW-MEDIUM'
            enhanced_assessment['recommendation'] = 'MONITOR - Some suspicious indicators detected'
        else:
            enhanced_assessment['risk_level'] = 'LOW'
            enhanced_assessment['recommendation'] = 'ALLOW - Appears legitimate according to hybrid analysis'
        
        # Add ML insights to threat indicators
        existing_threats = enhanced_assessment.get('threat_indicators', [])
        ml_threats = []
        
        if 'ensemble' in ml_predictions:
            ml_prob = ml_predictions['ensemble']['malware_probability']
            if ml_prob > 0.8:
                ml_threats.append(f'ML_CRITICAL: {ml_prob:.1%} malware probability')
            elif ml_prob > 0.6:
                ml_threats.append(f'ML_HIGH: {ml_prob:.1%} malware probability') 
            elif ml_prob > 0.4:
                ml_threats.append(f'ML_MEDIUM: {ml_prob:.1%} malware probability')
            
            # Add individual model consensus
            if 'individual_votes' in ml_predictions:
                malware_votes = ml_predictions.get('consensus', 0)
                total_models = len(ml_predictions['individual_votes'])
                if malware_votes >= total_models * 0.75:
                    ml_threats.append(f'ML_CONSENSUS: {malware_votes}/{total_models} models agree (HIGH confidence)')
                elif malware_votes >= total_models * 0.5:
                    ml_threats.append(f'ML_CONSENSUS: {malware_votes}/{total_models} models agree (MEDIUM confidence)')
        
        # Combine threats
        enhanced_assessment['threat_indicators'] = existing_threats + ml_threats
        
        # Add hybrid-specific fields
        enhanced_assessment['analysis_method'] = 'hybrid'
        enhanced_assessment['ml_confidence'] = confidence_level
        enhanced_assessment['hybrid_score'] = hybrid_score
        
        return enhanced_assessment
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of ML models and hybrid system"""
        status = {
            'ml_enabled': self.ml_enabled,
            'feature_extractor_ready': self.feature_extractor is not None,
            'hybrid_mode': self.ml_enabled,
            'analysis_mode': 'hybrid' if self.ml_enabled else 'rule_based_only'
        }
        
        if self.ml_enabled:
            model_summary = self.ml_classifier.get_model_summary()
            status.update({
                'models_available': model_summary.get('models_trained', []),
                'ensemble_available': model_summary.get('ensemble_available', False),
                'model_performance': model_summary.get('performance_metrics', {})
            })
        
        return status
    
    def train_ml_models_from_data(self, training_data_path: str) -> Dict[str, Any]:
        """
        Train ML models from CSV data
        
        Args:
            training_data_path: Path to CSV file with features and labels
            
        Returns:
            Training results
        """
        try:
            logger.info(f"📚 Training ML models from {training_data_path}")
            
            # Load training data
            if training_data_path.endswith('.csv'):
                df = pd.read_csv(training_data_path)
            else:
                logger.error("❌ Training data must be in CSV format")
                return {'error': 'Invalid data format'}
            
            # Assume last column is the label
            X = df.iloc[:, :-1].values
            y = df.iloc[:, -1].values
            
            logger.info(f"📊 Training data: {len(X)} samples, {X.shape[1]} features")
            
            # Train individual models
            model_scores = self.ml_classifier.train_individual_models(X, y)
            
            # Create ensemble
            ensemble_score = self.ml_classifier.create_ensemble_model(X, y)
            
            # Save performance metrics
            self.ml_classifier.save_performance_metrics()
            
            # Enable ML mode
            self.ml_enabled = True
            
            results = {
                'training_successful': True,
                'model_scores': model_scores,
                'ensemble_score': ensemble_score,
                'samples_trained': len(X),
                'features_used': X.shape[1]
            }
            
            logger.info("✅ ML model training completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"❌ ML model training failed: {e}")
            return {'error': str(e), 'training_successful': False}

def create_training_data_from_scans(scan_results_db_path: str, output_csv_path: str) -> bool:
    """
    Create training dataset from your existing scan results database
    
    Args:
        scan_results_db_path: Path to your scan_results.db file
        output_csv_path: Path to save the CSV training data
        
    Returns:
        Success status
    """
    try:
        import sqlite3
        
        logger.info(f"🗃️ Creating training data from {scan_results_db_path}")
        
        # Connect to your database
        conn = sqlite3.connect(scan_results_db_path)
        cursor = conn.cursor()
        
        # Query scan results
        cursor.execute("""
            SELECT analysis_results, risk_level, risk_score 
            FROM scan_results 
            WHERE analysis_results IS NOT NULL
        """)
        
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            logger.warning("⚠️ No scan results found in database")
            return False
        
        # Process results into training data
        feature_extractor = CyberSentinelsFeatureExtractor()
        training_data = []
        
        for analysis_json, risk_level, risk_score in results:
            try:
                # Parse analysis results
                analysis_results = json.loads(analysis_json) if isinstance(analysis_json, str) else analysis_json
                
                # Extract features
                features = feature_extractor.extract_features_from_analysis(analysis_results)
                
                # Create label (1 for HIGH/CRITICAL risk, 0 for LOW/MEDIUM)
                label = 1 if risk_level in ['HIGH', 'CRITICAL'] or risk_score >= 70 else 0
                
                # Combine features and label
                row = list(features) + [label]
                training_data.append(row)
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to process scan result: {e}")
                continue
        
        if not training_data:
            logger.error("❌ No valid training data created")
            return False
        
        # Create DataFrame and save
        feature_names = feature_extractor.feature_names + ['label']
        df = pd.DataFrame(training_data, columns=feature_names)
        df.to_csv(output_csv_path, index=False)
        
        logger.info(f"✅ Training data saved: {len(training_data)} samples, {len(feature_names)-1} features")
        logger.info(f"📊 Malware samples: {df['label'].sum()}, Benign samples: {len(df) - df['label'].sum()}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Training data creation failed: {e}")
        return False

if __name__ == "__main__":
    # Test the hybrid detector
    print("=== CYBERSENTINELS HYBRID DETECTOR TEST ===")
    
    # Initialize hybrid detector
    hybrid_detector = HybridAPKDetector()
    
    # Check model status
    status = hybrid_detector.get_model_status()
    print(f"\n📊 Model Status: {status}")
    
    # Test with dummy analysis results
    dummy_analysis = {
        'file_info': {'size': 15000000, 'sha256': 'test_hash'},
        'permission_analysis': {
            'total_permissions': 25,
            'dangerous_permissions': ['android.permission.READ_SMS'],
            'all_permissions': ['android.permission.INTERNET']
        },
        'behavioral_indicators': {'banking_trojan_score': 75},
        'indian_banking_check': {'impersonation_score': 80},
        'logo_analysis': {'match': True, 'similarity': 0.85},
        'risk_assessment': {
            'overall_score': 70,
            'risk_level': 'HIGH',
            'threat_indicators': ['banking_impersonation'],
            'recommendation': 'Block this APK'
        }
    }
    
    # Perform hybrid analysis
    print("\n🔬 Testing hybrid analysis...")
    hybrid_results = hybrid_detector.analyze_apk_hybrid("test.apk", dummy_analysis)
    
    print(f"✅ Hybrid analysis completed")
    print(f"📊 Analysis type: {hybrid_results.get('analysis_type', 'unknown')}")
    
    if 'hybrid_assessment' in hybrid_results:
        hybrid_assessment = hybrid_results['hybrid_assessment']
        print(f"🎯 Hybrid score: {hybrid_assessment.get('hybrid_score', 0):.1f}/100")
        print(f"🔒 Confidence: {hybrid_assessment.get('confidence_level', 'unknown')}")
    
    print("\n✅ Hybrid detector test completed!")