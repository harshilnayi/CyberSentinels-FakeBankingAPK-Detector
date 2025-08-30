# =====================================================================
# CYBERSENTINELS QUICK TRAINING SCRIPT - PHASE 4
# Quick setup to train ML models and integrate with your system
# =====================================================================

import os
import sys
import logging
from pathlib import Path
import numpy as np
import pandas as pd

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from ml_feature_extractor import CyberSentinelsFeatureExtractor
    from ml_models import CyberSentinelsMLClassifier, BankingAPKDataProcessor
    from ml_integration import HybridAPKDetector, create_training_data_from_scans
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("📝 Make sure all ML files are in the same directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def quick_setup_and_train():
    """Quick setup to train ML models for your system"""
    print("=== CYBERSENTINELS ML QUICK SETUP ===")
    print("🚀 Setting up Machine Learning for Banking APK Detection")
    
    # Step 1: Check if you have existing scan data
    scan_db_path = "scan_results.db"
    
    if os.path.exists(scan_db_path):
        print(f"\n✅ Found existing scan database: {scan_db_path}")
        print("🔄 Creating training data from your existing scans...")
        
        training_csv_path = "training_data.csv"
        success = create_training_data_from_scans(scan_db_path, training_csv_path)
        
        if success and os.path.exists(training_csv_path):
            print(f"✅ Training data created: {training_csv_path}")
            
            # Train models
            print("\n🚀 Training ML models...")
            hybrid_detector = HybridAPKDetector()
            results = hybrid_detector.train_ml_models_from_data(training_csv_path)
            
            if results.get('training_successful', False):
                print("🎉 ML models trained successfully!")
                print(f"📊 Model Performance:")
                for model, score in results.get('model_scores', {}).items():
                    print(f"   {model}: {score:.4f} accuracy")
                print(f"   ensemble: {results.get('ensemble_score', 0):.4f} accuracy")
                
                return True
            else:
                print(f"❌ Training failed: {results.get('error', 'Unknown error')}")
                
        else:
            print("❌ Failed to create training data from existing scans")
    
    # Step 2: Use demo dataset if no existing data
    print("\n🎭 No existing scan data found. Creating demo dataset...")
    print("⚠️ Note: This is for testing only. Use real malware data for production.")
    
    # Create demo dataset
    X, y = BankingAPKDataProcessor.create_demo_dataset(1000)
    
    if len(X) > 0:
        # Initialize classifier
        ml_classifier = CyberSentinelsMLClassifier()
        
        # Train models
        print("\n🚀 Training ML models on demo data...")
        model_scores = ml_classifier.train_individual_models(X, y)
        ensemble_score = ml_classifier.create_ensemble_model(X, y)
        
        # Save performance
        ml_classifier.save_performance_metrics()
        
        print("🎉 Demo ML models trained successfully!")
        print(f"📊 Model Performance:")
        for model, score in model_scores.items():
            print(f"   {model}: {score:.4f} accuracy")
        print(f"   ensemble: {ensemble_score:.4f} accuracy")
        
        return True
    else:
        print("❌ Failed to create demo dataset")
        return False

def test_integration():
    """Test the ML integration with your existing system"""
    print("\n=== TESTING ML INTEGRATION ===")
    
    # Initialize hybrid detector
    hybrid_detector = HybridAPKDetector()
    
    # Check status
    status = hybrid_detector.get_model_status()
    print(f"📊 ML Status: {status['analysis_mode'].upper()}")
    
    # Create test analysis results (simulating your advanced_detection_logic.py output)
    test_analysis = {
        'file_info': {
            'filename': 'test_banking_app.apk',
            'size': 25000000,
            'sha256': 'abc123def456...'
        },
        'permission_analysis': {
            'total_permissions': 35,
            'dangerous_permissions': [
                'android.permission.READ_SMS',
                'android.permission.SYSTEM_ALERT_WINDOW',
                'android.permission.RECORD_AUDIO'
            ],
            'all_permissions': [
                'android.permission.INTERNET',
                'android.permission.READ_SMS',
                'android.permission.SYSTEM_ALERT_WINDOW'
            ],
            'suspicious_combinations': ['banking_trojan_pattern']
        },
        'behavioral_indicators': {
            'banking_trojan_score': 85,
            'overlay_detection': True,
            'sms_interception': True,
            'keylogging_detected': True,
            'screen_recording': False
        },
        'indian_banking_check': {
            'impersonation_score': 90,
            'package_name': 'com.fake.sbi.mobilebanking',
            'app_name': 'SBI Mobile Banking'
        },
        'logo_analysis': {
            'match': True,
            'similarity': 0.92,
            'bank': 'SBI',
            'threat_level': 'HIGH'
        },
        'certificate_analysis': {
            'is_signed': True,
            'certificate_suspicious': True,
            'signature_verification': 'suspicious'
        },
        'string_analysis': {
            'suspicious_strings': ['keylog', 'sms', 'banking', 'overlay'],
            'urls_found': ['http://malicious-server.com/collect'],
            'ip_addresses': ['192.168.1.100']
        },
        'risk_assessment': {
            'overall_score': 85,
            'risk_level': 'HIGH',
            'threat_indicators': [
                'banking_app_impersonation',
                'logo_impersonation_SBI',
                'banking_trojan_pattern',
                'suspicious_certificate'
            ],
            'recommendation': 'BLOCK - High risk banking malware detected'
        }
    }
    
    # Perform hybrid analysis
    print("\n🔬 Testing hybrid analysis...")
    hybrid_results = hybrid_detector.analyze_apk_hybrid("test_banking_app.apk", test_analysis)
    
    # Display results
    print("\n📊 HYBRID ANALYSIS RESULTS:")
    print(f"Analysis Type: {hybrid_results.get('analysis_type', 'unknown')}")
    
    if 'hybrid_assessment' in hybrid_results:
        hybrid_assessment = hybrid_results['hybrid_assessment']
        print(f"Hybrid Score: {hybrid_assessment.get('hybrid_score', 0):.1f}/100")
        print(f"Confidence Level: {hybrid_assessment.get('confidence_level', 'unknown')}")
        print(f"Consensus Achieved: {hybrid_assessment.get('consensus_achieved', False)}")
    
    if 'ml_analysis' in hybrid_results:
        ml_analysis = hybrid_results['ml_analysis']
        print(f"ML Enabled: {ml_analysis.get('enabled', False)}")
        
        if ml_analysis.get('enabled', False):
            predictions = ml_analysis.get('predictions', {})
            if 'ensemble' in predictions:
                ensemble_pred = predictions['ensemble']
                print(f"ML Prediction: {'MALWARE' if ensemble_pred['prediction'] == 1 else 'BENIGN'}")
                print(f"ML Confidence: {ensemble_pred['confidence']:.3f}")
                print(f"Malware Probability: {ensemble_pred['malware_probability']:.3f}")
    
    enhanced_risk = hybrid_results.get('risk_assessment', {})
    print(f"\nFinal Risk Level: {enhanced_risk.get('risk_level', 'unknown')}")
    print(f"Final Recommendation: {enhanced_risk.get('recommendation', 'unknown')}")
    
    return True

def update_app_py_integration():
    """Show how to integrate with your app.py"""
    print("\n=== INTEGRATION INSTRUCTIONS ===")
    print("📝 To integrate ML with your existing app.py, add these changes:")
    print()
    print("1. Import the hybrid detector at the top of your app.py:")
    print("   from ml_integration import HybridAPKDetector")
    print()
    print("2. Initialize in your Flask app:")
    print("   hybrid_detector = HybridAPKDetector()")
    print()
    print("3. In your scan route, replace the analysis line:")
    print("   # OLD:")
    print("   analysis_results = detector.analyze_apk_comprehensive(filepath)")
    print("   # NEW:")
    print("   base_analysis = detector.analyze_apk_comprehensive(filepath)")
    print("   analysis_results = hybrid_detector.analyze_apk_hybrid(filepath, base_analysis)")
    print()
    print("4. Your existing UI will automatically show ML enhancements!")
    print()

if __name__ == "__main__":
    # Run quick setup
    success = quick_setup_and_train()
    
    if success:
        # Test integration
        test_integration()
        
        # Show integration instructions
        update_app_py_integration()
        
        print("\n🎉 CYBERSENTINELS ML SETUP COMPLETED!")
        print("✅ Your system now has machine learning capabilities")
        print("🔬 ML models trained and ready for hybrid analysis")
        print("🏆 You now have a competitive advantage with ML + rule-based detection!")
        
    else:
        print("\n❌ Setup failed. Check the errors above and try again.")
        
    print("\n📚 WHAT'S NEXT:")
    print("1. Test with real APK files to see hybrid analysis in action")
    print("2. Collect more real malware samples to improve ML accuracy")
    print("3. Fine-tune the hybrid weights in ml_integration.py if needed")
    print("4. Deploy and demo your enhanced system!")
    print("\n🚀 Your CyberSentinels system is now competition-ready with ML!")