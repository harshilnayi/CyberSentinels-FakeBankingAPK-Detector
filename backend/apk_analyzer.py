import zipfile, os

def analyze_apk(file):
    # Save temp
    temp_path = "temp.apk"
    file.save(temp_path)

    # Just check manifest and permissions as starting point
    try:
        with zipfile.ZipFile(temp_path, 'r') as apk:
            namelist = apk.namelist()
            suspicious = []
            if "AndroidManifest.xml" in namelist:
                suspicious.append("Manifest present (ready for parsing)")
            
            # Basic fake check example
            if "bank" in temp_path.lower():
                suspicious.append("App name contains 'bank'")
            
        score = len(suspicious)
        verdict = "Safe ✅" if score == 0 else ("Medium ⚠️" if score == 1 else "High Risk ❌")
        
        return {"score": score, "verdict": verdict, "details": suspicious}
    except Exception as e:
        return {"error": str(e)}
