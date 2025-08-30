#!/usr/bin/env python3
# CyberSentinels ML-Enhanced Launcher
import os
import sys

def main():
    print("🚀 Starting CyberSentinels ML-Enhanced System...")
    
    # Try to use enhanced app first
    try:
        from enhanced_app import app
        print("✅ ML-Enhanced version loaded!")
        app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    except ImportError:
        # Fallback to original app
        try:
            from app import app
            print("⚠️  Using original version - ML features not available")
            app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
        except ImportError:
            print("❌ No app.py found. Please check your installation.")
            sys.exit(1)

if __name__ == "__main__":
    main()
