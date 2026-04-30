from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import time
import joblib
import os
import re
import socket
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ==========================================
# 1. تحميل نماذج الذكاء الاصطناعي 
# ==========================================
models = {'en': None, 'ar': None}
vectorizers = {'en': None, 'ar': None}

try:
    if os.path.exists('arabic_phishing_model.pkl'):
        models['ar'] = joblib.load('arabic_phishing_model.pkl')
        vectorizers['ar'] = joblib.load('arabic_tfidf_vectorizer.pkl')
    if os.path.exists('phishing_model.pkl'):
        models['en'] = joblib.load('phishing_model.pkl')
        vectorizers['en'] = joblib.load('tfidf_vectorizer.pkl')
except Exception as e:
    print(f"[!] خطأ في تحميل النماذج: {e}")

# ==========================================
# 2. دوال الحماية والمساعدة (SOC Rules)
# ==========================================
def detect_language(text):
    if re.search("[\u0600-\u06FF]", text): return 'ar'
    return 'en'

def is_safe_url(url):
    """حماية SSRF لمنع استطلاع الشبكة الداخلية للجامعة"""
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        ip_address = socket.gethostbyname(hostname)
        private_prefixes = ("127.", "10.", "192.168.", "172.", "0.0.0.0")
        if any(ip_address.startswith(prefix) for prefix in private_prefixes):
            return False
        return True
    except Exception:
        return False

def calculate_url_risk(url):
    risk = 0
    reasons = []
    
    if url.startswith("http://"):
        risk += 35
        reasons.append("غير مشفر (HTTP) مما يسهل اعتراض البيانات")
        
    domain = urlparse(url).netloc
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        risk += 40
        reasons.append("يستخدم عنوان IP صريح بدلاً من اسم نطاق رسمي")
        
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'free', 'win', 'paypal']
    if any(word in url.lower() for word in suspicious_keywords):
        risk += 25
        reasons.append("يحتوي على كلمات شائعة في هجمات الهندسة الاجتماعية")
            
    if len(url) > 75:
        risk += 15
        reasons.append("الرابط طويل جداً (أسلوب متبع لإخفاء الوجهة الحقيقية)")
        
    risk = min(risk, 99)
    if risk == 0:
        risk = 5
        reasons.append("هيكل الرابط يبدو طبيعياً وآمناً")
        
    return risk, reasons

# ==========================================
# 3. المسارات البرمجية (Routes)
# ==========================================

# هذا هو المسار الذي كان مفقوداً ويسبب Not Found
@app.route('/')
def home():
    return render_template('index.html')

@app.route("/analyze_full", methods=["POST", "OPTIONS"])
def analyze_full():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    data = request.get_json() or {}
    full_text = data.get("text", "").strip()

    if not full_text:
        return jsonify({"error": "يرجى إدخال النص"}), 400

    urls_found = re.findall(r'https?://[^\s]+', full_text)
    lang = detect_language(full_text)
    text_analysis = {}
    
    # تحليل النص بالذكاء الاصطناعي
    if models[lang] is not None and vectorizers[lang] is not None:
        try:
            text_without_urls = re.sub(r'https?://[^\s]+', '', full_text).strip()
            if len(text_without_urls) > 5:
                text_vectorized = vectorizers[lang].transform([text_without_urls])
                prediction = models[lang].predict(text_vectorized)[0]
                probabilities = models[lang].predict_proba(text_vectorized)[0]
                
                text_analysis = {
                    "analyzed": True,
                    "is_phishing": bool(prediction == 1),
                    "confidence": round(max(probabilities) * 100, 2),
                    "language": "العربية" if lang == 'ar' else "الإنجليزية"
                }
            else:
                text_analysis = {"analyzed": False, "reason": "النص المدخل عبارة عن رابط فقط بدون سياق رسالة."}
        except Exception as e:
            text_analysis = {"analyzed": False, "error": str(e)}
    else:
        text_analysis = {"analyzed": False, "error": "نموذج الذكاء الاصطناعي غير متوفر حالياً."}

    # تحليل الروابط بتفصيل شديد
    urls_analysis = []
    for url in urls_found:
        risk_score, risk_reasons = calculate_url_risk(url)
        parsed = urlparse(url)
        
        is_reachable = False
        status_code = "لم يتم الفحص"
        elapsed = 0
        
        if not is_safe_url(url):
            status_code = "محظور أمنياً (SSRF)"
            risk_score = 100
            risk_reasons.append("محاولة وصول غير مصرح بها لعنوان IP داخلي")
        else:
            try:
                start = time.time()
                res = requests.head(url, timeout=5, allow_redirects=True)
                if res.status_code >= 400:
                    res = requests.get(url, timeout=5, allow_redirects=True)
                    
                elapsed = round(time.time() - start, 3)
                status_code = res.status_code
                if status_code < 400:
                    is_reachable = True
            except requests.exceptions.RequestException:
                status_code = "فشل الاتصال"
            
        urls_analysis.append({
            "url": url,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "is_reachable": is_reachable,
            "status_code": status_code,
            "elapsed_seconds": elapsed,
            "protocol": parsed.scheme.upper(),
            "domain": parsed.netloc
        })

    return jsonify({
        "text_analysis": text_analysis,
        "urls_analysis": urls_analysis
    })

if __name__ == "__main__":
    # الحصول على البورت من السيرفر، وإذا لم يوجد نستخدم 5000 كاحتياط
    port = int(os.environ.get("PORT", 5000))
    # إيقاف debug في بيئة الإنتاج لزيادة الأمان والأداء
    app.run(host="0.0.0.0", port=port, debug=False)
