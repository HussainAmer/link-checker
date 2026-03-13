from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import time
import joblib
import os
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ==========================================
# 1. تحميل نماذج الذكاء الاصطناعي 
# ==========================================
ENG_MODEL_PATH = 'phishing_model.pkl'
ENG_VECTORIZER_PATH = 'tfidf_vectorizer.pkl'
AR_MODEL_PATH = 'arabic_phishing_model.pkl'
AR_VECTORIZER_PATH = 'arabic_tfidf_vectorizer.pkl'

models = {'en': None, 'ar': None}
vectorizers = {'en': None, 'ar': None}

if os.path.exists(ENG_MODEL_PATH) and os.path.exists(ENG_VECTORIZER_PATH):
    try:
        models['en'] = joblib.load(ENG_MODEL_PATH)
        vectorizers['en'] = joblib.load(ENG_VECTORIZER_PATH)
        print("✅ تم تحميل النموذج [الإنجليزي] بنجاح.")
    except Exception as e: print(f"❌ خطأ: {e}")

if os.path.exists(AR_MODEL_PATH) and os.path.exists(AR_VECTORIZER_PATH):
    try:
        models['ar'] = joblib.load(AR_MODEL_PATH)
        vectorizers['ar'] = joblib.load(AR_VECTORIZER_PATH)
        print("✅ تم تحميل النموذج [العربي] بنجاح.")
    except Exception as e: print(f"❌ خطأ: {e}")

# ==========================================
# 2. دوال مساعدة
# ==========================================
def detect_language(text):
    if re.search("[\u0600-\u06FF]", text): return 'ar'
    return 'en'

def calculate_url_risk(url):
    risk = 0
    reasons = []
    
    if url.startswith("http://"):
        risk += 35
        reasons.append("غير مشفر (HTTP)")
        
    domain = url.split('/')[2] if len(url.split('/')) > 2 else ""
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        risk += 40
        reasons.append("يستخدم عنوان IP بدلاً من اسم نطاق رسمي")
        
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'free', 'win', 'paypal']
    for word in suspicious_keywords:
        if word in url.lower():
            risk += 25
            reasons.append(f"يحتوي على كلمة خداع شائعة ({word})")
            break 
            
    if len(url) > 75:
        risk += 15
        reasons.append("الرابط طويل جداً (أسلوب لإخفاء الوجهة الحقيقية)")
        
    risk = min(risk, 99)
    if risk == 0:
        risk = 5
        reasons.append("هيكل الرابط يبدو طبيعياً وآمناً")
        
    return risk, reasons

# ==========================================
# 3. المسار المدمج (الرسالة + التفاصيل الكاملة للرابط)
# ==========================================
@app.route("/analyze_full", methods=["POST", "OPTIONS"])
def analyze_full():
    # 1. التعامل مع طلبات OPTIONS (CORS)
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    # 2. استخراج البيانات (يجب أن يكون خارج شرط OPTIONS ليعمل مع طلبات POST)
    data = request.get_json() or {}
    full_text = data.get("text", "").strip()

    # 3. التأكد من وجود النص
    if not full_text:
        return jsonify({"error": "يرجى إدخال النص"}), 400

    # 4. بقية العمليات (Regex, Detection, etc.)
    urls_found = re.findall(r'https?://[^\s]+', full_text)
    lang = detect_language(full_text)
    text_analysis = {}
    
    if models[lang] is not None and vectorizers[lang] is not None:
        try:
            text_without_urls = re.sub(r'https?://[^\s]+', '', full_text).strip()
            if len(text_without_urls) > 5:
                text_vectorized = vectorizers[lang].transform([text_without_urls])
                prediction = models[lang].predict(text_vectorized)[0]
                probabilities = models[lang].predict_proba(text_vectorized)[0]
                
                is_phishing = bool(prediction == 1)
                confidence = round(max(probabilities) * 100, 2)
                
                text_analysis = {
                    "analyzed": True,
                    "is_phishing": is_phishing,
                    "confidence": confidence,
                    "language": "العربية" if lang == 'ar' else "الإنجليزية"
                }
            else:
                text_analysis = {"analyzed": False, "reason": "النص المدخل عبارة عن رابط فقط بدون سياق رسالة."}
        except Exception as e:
            text_analysis = {"analyzed": False, "error": str(e)}
    else:
        text_analysis = {"analyzed": False, "error": "نموذج الذكاء الاصطناعي غير متوفر."}

    # تحليل الروابط المستخرجة (بشكل مفصل جداً)
    urls_analysis = []
    for url in urls_found:
        risk_score, risk_reasons = calculate_url_risk(url)
        
        # استخراج الهيكل
        parsed = urlparse(url)
        protocol = parsed.scheme.upper()
        domain = parsed.netloc

        is_reachable = False
        status_code = "فشل الاتصال"
        elapsed = 0
        
        # فحص الاتصال الحقيقي
        try:
            start = time.time()
            res = requests.head(url, timeout=5, allow_redirects=True)
            if res.status_code >= 400: # إذا منع الـ HEAD نستخدم GET
                res = requests.get(url, timeout=5, allow_redirects=True)
                
            elapsed = round(time.time() - start, 3)
            status_code = res.status_code
            if status_code < 400:
                is_reachable = True
        except:
            pass
            
        urls_analysis.append({
            "url": url,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
            "is_reachable": is_reachable,
            "status_code": status_code,
            "elapsed_seconds": elapsed,
            "protocol": protocol,
            "domain": domain
        })

    return jsonify({
        "original_text": full_text,
        "text_analysis": text_analysis,
        "urls_analysis": urls_analysis
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
