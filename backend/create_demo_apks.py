import zipfile
import os

def create_banking_trojans():
    """Create 5 different banking trojans for demo"""
    
    trojans = [
        {
            'name': 'fake-sbi-mobile.apk',
            'package': 'com.fake.sbi.mobile',
            'app_name': 'SBI Mobile Banking',
            'permissions': ['READ_SMS', 'SEND_SMS', 'SYSTEM_ALERT_WINDOW', 'CAMERA', 'RECORD_AUDIO'],
            'threat_level': 'HIGH'
        },
        {
            'name': 'malicious-paytm.apk', 
            'package': 'com.evil.paytm.clone',
            'app_name': 'Paytm Wallet',
            'permissions': ['READ_SMS', 'BIND_ACCESSIBILITY_SERVICE', 'SYSTEM_ALERT_WINDOW'],
            'threat_level': 'CRITICAL'
        },
        {
            'name': 'fake-phonepe.apk',
            'package': 'com.malware.phonepe',
            'app_name': 'PhonePe Payment App', 
            'permissions': ['SEND_SMS', 'READ_CONTACTS', 'CAMERA'],
            'threat_level': 'MEDIUM'
        },
        {
            'name': 'legitimate-calculator.apk',
            'package': 'com.android.calculator2',
            'app_name': 'Calculator',
            'permissions': ['INTERNET'],
            'threat_level': 'LOW'
        },
        {
            'name': 'banking-overlay-trojan.apk',
            'package': 'com.overlay.banking.stealer',
            'app_name': 'Mobile Banking',
            'permissions': ['READ_SMS', 'SEND_SMS', 'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS'],
            'threat_level': 'CRITICAL'
        }
    ]
    
    for trojan in trojans:
        create_apk(trojan)
        print(f"✅ Created {trojan['name']} - {trojan['threat_level']} risk")

def create_apk(trojan_data):
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{trojan_data['package']}">
    
    {''.join([f'<uses-permission android:name="android.permission.{perm}" />' for perm in trojan_data['permissions']])}
    
    <application android:label="{trojan_data['app_name']}" android:icon="@drawable/ic_launcher">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service android:name=".OverlayService" />
        <service android:name=".AccessibilityService" 
                android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" />
        <receiver android:name=".SmsReceiver">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>'''

    dex_content = f'''Banking trojan content for {trojan_data['app_name']}:
SYSTEM_ALERT_WINDOW overlay attack
AccessibilityService keylogging
SMS interception capabilities
Banking credential theft
Screen overlay malware
'''.encode()

    with zipfile.ZipFile(trojan_data['name'], 'w') as apk:
        apk.writestr('AndroidManifest.xml', manifest.encode())
        apk.writestr('classes.dex', dex_content)
        apk.writestr('res/drawable/ic_launcher.png', b'fake_icon')

if __name__ == "__main__":
    create_banking_trojans()
