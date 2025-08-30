# =====================================================================
# CYBERSENTINELS ML MODELS - PHASE 2  
# Banking APK Detection Machine Learning Models
# Implements Random Forest, SVM, Naive Bayes, and Ensemble
# =====================================================================

import numpy as np
import pandas as pd
import pickle
import joblib
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path

# Scikit-learn imports
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberSentinelsMLClassifier:
    """
    Advanced ML Classifier Suite for CyberSentinels Banking APK Detection
    Implements hybrid ensemble approach with multiple algorithms
    """
    
    def __init__(self, model_save_path: str = "trained_models"):
        self.model_save_path = Path(model_save_path)
        self.model_save_path.mkdir(exist_ok=True)
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        self.ensemble_model = None
        self.feature_importance = None
        self.model_performance = {}
        
        # Training configuration
        self.random_state = 42
        self.test_size = 0.2
        self.cv_folds = 5
        
        logger.info("✅ CyberSentinels ML Classifier initialized")
        
    def _initialize_models(self):
        """Initialize all ML models with optimized hyperparameters"""
        
        # 1. RANDOM FOREST - Primary Classifier (97.9% accuracy benchmark)
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=200,           # More trees for better performance
            max_depth=20,               # Prevent overfitting
            min_samples_split=5,        # Minimum samples to split
            min_samples_leaf=2,         # Minimum samples in leaf
            max_features='sqrt',        # Feature selection
            bootstrap=True,             # Bootstrap sampling
            random_state=self.random_state,
            n_jobs=-1,                  # Use all cores
            class_weight='balanced',    # Handle imbalanced data
            oob_score=True             # Out-of-bag scoring
        )
        
        # 2. SVM - Secondary Classifier (96.3% accuracy benchmark)  
        self.models['svm'] = SVC(
            kernel='rbf',              # RBF kernel for non-linear patterns
            C=1.0,                     # Regularization parameter
            gamma='scale',             # Kernel coefficient
            probability=True,          # Enable probability estimates
            random_state=self.random_state,
            class_weight='balanced'    # Handle imbalanced data
        )
        
        # 3. GAUSSIAN NAIVE BAYES - Fast Classifier (95.83% accuracy benchmark)
        self.models['naive_bayes'] = GaussianNB(
            var_smoothing=1e-9         # Smoothing parameter
        )
        
        # 4. Initialize scalers for each model
        self.scalers['random_forest'] = None  # RF doesn't need scaling
        self.scalers['svm'] = StandardScaler()  # SVM needs scaling
        self.scalers['naive_bayes'] = RobustScaler()  # NB benefits from robust scaling
        
        logger.info("✅ ML models initialized with optimized hyperparameters")
        
    def train_individual_models(self, X: np.ndarray, y: np.ndarray, 
                               feature_names: List[str] = None) -> Dict[str, float]:
        """
        Train all individual ML models
        
        Args:
            X: Feature matrix
            y: Target labels (0=benign, 1=malware)
            feature_names: List of feature names
            
        Returns:
            Dictionary of model accuracies
        """
        try:
            self._initialize_models()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, 
                random_state=self.random_state, 
                stratify=y
            )
            
            logger.info(f"📊 Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")
            
            model_scores = {}
            
            for model_name, model in self.models.items():
                logger.info(f"🚀 Training {model_name}...")
                
                # Scale features if needed
                scaler = self.scalers[model_name]
                if scaler is not None:
                    X_train_scaled = scaler.fit_transform(X_train)
                    X_test_scaled = scaler.transform(X_test)
                else:
                    X_train_scaled = X_train
                    X_test_scaled = X_test
                
                # Train model
                start_time = datetime.now()
                model.fit(X_train_scaled, y_train)
                training_time = (datetime.now() - start_time).total_seconds()
                
                # Evaluate model
                y_pred = model.predict(X_test_scaled)
                y_prob = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else None
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                auc_score = roc_auc_score(y_test, y_prob) if y_prob is not None else 0
                
                # Cross-validation score
                cv_scores = cross_val_score(model, X_train_scaled, y_train, 
                                          cv=self.cv_folds, scoring='accuracy')
                
                # Store performance metrics
                self.model_performance[model_name] = {
                    'accuracy': accuracy,
                    'auc_score': auc_score,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'training_time': training_time,
                    'classification_report': classification_report(y_test, y_pred, output_dict=True),
                    'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
                }
                
                model_scores[model_name] = accuracy
                
                logger.info(f"✅ {model_name}: {accuracy:.4f} accuracy, {auc_score:.4f} AUC, "
                           f"{cv_scores.mean():.4f}±{cv_scores.std():.4f} CV")
                
                # Save model
                self._save_individual_model(model_name, model, scaler)
            
            # Extract feature importance from Random Forest
            if 'random_forest' in self.models and feature_names:
                rf_model = self.models['random_forest']
                self.feature_importance = rf_model.feature_importances_
                
                # Save feature importance
                importance_data = list(zip(feature_names, self.feature_importance))
                importance_data.sort(key=lambda x: x[1], reverse=True)
                
                importance_path = self.model_save_path / "feature_importance.json"
                with open(importance_path, 'w') as f:
                    json.dump({
                        'feature_importance': [{'feature': name, 'importance': float(imp)} 
                                             for name, imp in importance_data],
                        'top_10_features': importance_data[:10]
                    }, f, indent=2)
                
                logger.info(f"💎 Top 3 important features: {importance_data[:3]}")
            
            return model_scores
            
        except Exception as e:
            logger.error(f"❌ Model training failed: {e}")
            return {}
    
    def create_ensemble_model(self, X: np.ndarray, y: np.ndarray) -> float:
        """
        Create ensemble voting classifier combining all models
        
        Args:
            X: Feature matrix
            y: Target labels
            
        Returns:
            Ensemble accuracy
        """
        try:
            logger.info("🎯 Creating ensemble voting classifier...")
            
            # Prepare models for ensemble (with scaling pipelines)
            ensemble_models = []
            
            for model_name, model in self.models.items():
                scaler = self.scalers[model_name]
                
                if scaler is not None:
                    # Create pipeline with scaler
                    pipeline = Pipeline([
                        ('scaler', scaler),
                        ('classifier', model)
                    ])
                    ensemble_models.append((model_name, pipeline))
                else:
                    ensemble_models.append((model_name, model))
            
            # Create voting classifier
            self.ensemble_model = VotingClassifier(
                estimators=ensemble_models,
                voting='soft',  # Use probability-based voting
                n_jobs=-1
            )
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, 
                random_state=self.random_state, 
                stratify=y
            )
            
            # Train ensemble
            start_time = datetime.now()
            self.ensemble_model.fit(X_train, y_train)
            training_time = (datetime.now() - start_time).total_seconds()
            
            # Evaluate ensemble
            y_pred = self.ensemble_model.predict(X_test)
            y_prob = self.ensemble_model.predict_proba(X_test)[:, 1]
            
            accuracy = accuracy_score(y_test, y_pred)
            auc_score = roc_auc_score(y_test, y_prob)
            
            # Cross-validation
            cv_scores = cross_val_score(self.ensemble_model, X_train, y_train, 
                                      cv=self.cv_folds, scoring='accuracy')
            
            # Store ensemble performance
            self.model_performance['ensemble'] = {
                'accuracy': accuracy,
                'auc_score': auc_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'training_time': training_time,
                'classification_report': classification_report(y_test, y_pred, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            logger.info(f"🏆 Ensemble: {accuracy:.4f} accuracy, {auc_score:.4f} AUC, "
                       f"{cv_scores.mean():.4f}±{cv_scores.std():.4f} CV")
            
            # Save ensemble model
            ensemble_path = self.model_save_path / "ensemble_model.pkl"
            joblib.dump(self.ensemble_model, ensemble_path)
            logger.info(f"💾 Ensemble model saved to {ensemble_path}")
            
            return accuracy
            
        except Exception as e:
            logger.error(f"❌ Ensemble creation failed: {e}")
            return 0.0
    
    def predict_single(self, features: np.ndarray, use_ensemble: bool = True) -> Dict[str, Any]:
        """
        Predict single APK with confidence scores
        
        Args:
            features: Feature vector (1D array)
            use_ensemble: Use ensemble model if available
            
        Returns:
            Prediction results with confidence
        """
        try:
            features = features.reshape(1, -1)
            results = {}
            
            if use_ensemble and self.ensemble_model is not None:
                # Ensemble prediction
                prediction = self.ensemble_model.predict(features)[0]
                probabilities = self.ensemble_model.predict_proba(features)[0]
                
                results['ensemble'] = {
                    'prediction': int(prediction),
                    'confidence': float(max(probabilities)),
                    'malware_probability': float(probabilities[1]),
                    'benign_probability': float(probabilities[0])
                }
                
                # Get individual model votes
                individual_votes = {}
                for name, estimator in self.ensemble_model.named_estimators_.items():
                    vote = estimator.predict(features)[0]
                    vote_prob = estimator.predict_proba(features)[0] if hasattr(estimator, 'predict_proba') else [0.5, 0.5]
                    
                    individual_votes[name] = {
                        'vote': int(vote),
                        'confidence': float(max(vote_prob)),
                        'malware_prob': float(vote_prob[1])
                    }
                
                results['individual_votes'] = individual_votes
                results['consensus'] = len([v for v in individual_votes.values() if v['vote'] == 1])
                
            else:
                # Individual model predictions
                for model_name, model in self.models.items():
                    scaler = self.scalers[model_name]
                    
                    # Scale features if needed
                    if scaler is not None:
                        features_scaled = scaler.transform(features)
                    else:
                        features_scaled = features
                    
                    prediction = model.predict(features_scaled)[0]
                    
                    if hasattr(model, 'predict_proba'):
                        probabilities = model.predict_proba(features_scaled)[0]
                        confidence = max(probabilities)
                        malware_prob = probabilities[1]
                    else:
                        confidence = 0.8  # Default for models without probability
                        malware_prob = 0.8 if prediction == 1 else 0.2
                    
                    results[model_name] = {
                        'prediction': int(prediction),
                        'confidence': float(confidence),
                        'malware_probability': float(malware_prob)
                    }
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Prediction failed: {e}")
            return {'error': str(e)}
    
    def get_model_summary(self) -> Dict[str, Any]:
        """Get comprehensive model performance summary"""
        return {
            'models_trained': list(self.models.keys()),
            'ensemble_available': self.ensemble_model is not None,
            'performance_metrics': self.model_performance,
            'training_config': {
                'test_size': self.test_size,
                'cv_folds': self.cv_folds,
                'random_state': self.random_state
            },
            'model_save_path': str(self.model_save_path)
        }
    
    def _save_individual_model(self, model_name: str, model: Any, scaler: Any = None):
        """Save individual model and scaler"""
        try:
            model_path = self.model_save_path / f"{model_name}_model.pkl"
            joblib.dump(model, model_path)
            
            if scaler is not None:
                scaler_path = self.model_save_path / f"{model_name}_scaler.pkl"
                joblib.dump(scaler, scaler_path)
            
            logger.info(f"💾 {model_name} saved successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to save {model_name}: {e}")
    
    def load_models(self) -> bool:
        """Load pre-trained models from disk"""
        try:
            self._initialize_models()
            
            # Load individual models
            for model_name in self.models.keys():
                model_path = self.model_save_path / f"{model_name}_model.pkl"
                scaler_path = self.model_save_path / f"{model_name}_scaler.pkl"
                
                if model_path.exists():
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"✅ Loaded {model_name} model")
                    
                    if scaler_path.exists():
                        self.scalers[model_name] = joblib.load(scaler_path)
                        logger.info(f"✅ Loaded {model_name} scaler")
            
            # Load ensemble model
            ensemble_path = self.model_save_path / "ensemble_model.pkl"
            if ensemble_path.exists():
                self.ensemble_model = joblib.load(ensemble_path)
                logger.info("✅ Loaded ensemble model")
            
            # Load performance metrics
            performance_path = self.model_save_path / "model_performance.json"
            if performance_path.exists():
                with open(performance_path, 'r') as f:
                    self.model_performance = json.load(f)
                logger.info("✅ Loaded performance metrics")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Model loading failed: {e}")
            return False
    
    def save_performance_metrics(self):
        """Save performance metrics to file"""
        try:
            performance_path = self.model_save_path / "model_performance.json"
            with open(performance_path, 'w') as f:
                json.dump(self.model_performance, f, indent=2, default=str)
            
            logger.info(f"💾 Performance metrics saved to {performance_path}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save performance metrics: {e}")

class BankingAPKDataProcessor:
    """Data processor for banking APK datasets"""
    
    @staticmethod
    def create_demo_dataset(num_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create demo dataset for testing ML models
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            Tuple of (features, labels)
        """
        try:
            logger.info(f"🎭 Creating demo dataset with {num_samples} samples...")
            
            # Feature dimensions based on CyberSentinelsFeatureExtractor
            num_features = 80  # Total features from feature extractor
            
            # Generate synthetic features
            np.random.seed(42)
            
            # Create benign samples (60% of data)
            benign_count = int(num_samples * 0.6)
            malware_count = num_samples - benign_count
            
            # Benign app characteristics
            benign_features = []
            for _ in range(benign_count):
                features = np.random.random(num_features)
                
                # Benign apps have fewer dangerous permissions
                features[11] = np.random.uniform(0, 0.3)  # dangerous_permissions
                features[26] = 0  # banking_trojan_score (normalized)
                features[34] = 0  # banking_trojan_pattern
                features[43] = np.random.uniform(0, 0.2)  # impersonation_score
                features[45] = 0  # logo_match_detected
                
                benign_features.append(features)
            
            # Malware app characteristics  
            malware_features = []
            for _ in range(malware_count):
                features = np.random.random(num_features)
                
                # Malware apps have more suspicious characteristics
                features[11] = np.random.uniform(0.5, 1.0)  # dangerous_permissions
                features[26] = np.random.uniform(0.4, 1.0)  # banking_trojan_score
                features[27] = np.random.choice([0, 1])  # overlay_detection
                features[28] = np.random.choice([0, 1])  # sms_interception
                features[34] = np.random.choice([0, 1])  # banking_trojan_pattern
                features[43] = np.random.uniform(0.6, 1.0)  # impersonation_score
                features[45] = np.random.choice([0, 1])  # logo_match_detected
                
                malware_features.append(features)
            
            # Combine features and create labels
            X = np.vstack([benign_features, malware_features])
            y = np.hstack([np.zeros(benign_count), np.ones(malware_count)])
            
            # Shuffle data
            shuffle_idx = np.random.permutation(len(X))
            X = X[shuffle_idx]
            y = y[shuffle_idx]
            
            logger.info(f"✅ Demo dataset created: {len(X)} samples, {X.shape[1]} features")
            logger.info(f"📊 Benign: {benign_count}, Malware: {malware_count}")
            
            return X, y.astype(int)
            
        except Exception as e:
            logger.error(f"❌ Demo dataset creation failed: {e}")
            return np.array([]), np.array([])

if __name__ == "__main__":
    # Test the ML classifier
    print("=== CYBERSENTINELS ML CLASSIFIER TEST ===")
    
    # Initialize classifier
    ml_classifier = CyberSentinelsMLClassifier()
    
    # Create demo dataset
    X, y = BankingAPKDataProcessor.create_demo_dataset(1000)
    
    if len(X) > 0:
        # Train individual models
        print("\n🚀 Training individual models...")
        model_scores = ml_classifier.train_individual_models(X, y)
        
        # Create ensemble
        print("\n🎯 Creating ensemble model...")
        ensemble_score = ml_classifier.create_ensemble_model(X, y)
        
        # Save performance metrics
        ml_classifier.save_performance_metrics()
        
        # Print summary
        print("\n📊 MODEL PERFORMANCE SUMMARY:")
        for model_name, score in model_scores.items():
            print(f"  {model_name}: {score:.4f} accuracy")
        print(f"  ensemble: {ensemble_score:.4f} accuracy")
        
        # Test single prediction
        print("\n🔍 Testing single prediction...")
        test_features = X[0]
        prediction = ml_classifier.predict_single(test_features)
        print(f"Prediction result: {prediction}")
        
        print("\n✅ ML Classifier test completed successfully!")
    else:
        print("❌ Failed to create demo dataset")