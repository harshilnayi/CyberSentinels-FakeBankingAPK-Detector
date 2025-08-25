import os
has_sig = any(n.startswith('META-INF/') and (n.endswith('.RSA') or n.endswith('.DSA') or n.endswith('.EC')) for n in names)
if not has_sig:
score += 30
flags.append('No signature file in META-INF')


# Multiple .dex files may indicate packing/obfuscation
dex_count = sum(1 for n in names if n.endswith('.dex'))
if dex_count >= 4:
score += 10
flags.append(f'{dex_count} dex files present')


# Suspicious file name terms
lower_names = ' '.join(names).lower()
suspicious_hits = [t for t in SUSPICIOUS_TERMS if t in lower_names]
if suspicious_hits:
add = min(20, 5 * len(suspicious_hits))
score += add
flags.append(f"Suspicious terms in assets/resources: {', '.join(sorted(set(suspicious_hits)))}")


# Crude URL scan inside first dex (optional)
try:
first_dex = next(n for n in names if n.endswith('.dex'))
with zf.open(first_dex) as fh:
data = fh.read()
http_count = data.count(b'http://')
https_count = data.count(b'https://')
if http_count > 0:
score += 10
flags.append('Insecure URLs (http://) found in code')
if (http_count + https_count) > 30:
score += 15
flags.append('High number of hardcoded URLs in code')
except StopIteration:
pass
except Exception:
# Ignore URL scan errors; keep other signals
pass


except zipfile.BadZipFile:
score += 60
flags.append('APK zip structure is invalid/corrupted')


# Normalize and classify
score = max(0, min(100, score))
if score >= 60:
status = 'Fake'
elif score >= 30:
status = 'Suspicious'
else:
status = 'Safe'


return {
'status': status,
'risk_score': int(score),
'flags': flags,
}