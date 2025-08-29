import zipfile

# Create a fake banking trojan for testing
manifest = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.fake.sbi.mobile">
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application android:label="Fake SBI Banking">
        <activity android:name=".MainActivity" />
    </application>
</manifest>'''

with zipfile.ZipFile('fake-sbi-banking.apk', 'w') as apk:
    apk.writestr('AndroidManifest.xml', manifest)
    apk.writestr('classes.dex', b'fake banking trojan content')

print("✅ Created fake-sbi-banking.apk for testing")
