import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os

print("="*50)
print("[*] بدء نظام التدريب المزدوج (العربي والإنجليزي)")
print("="*50)

# دالة برمجية (Function) لتدريب أي نموذج لتقليل تكرار الكود
def train_language_model(csv_file, model_name, vectorizer_name, is_arabic=False):
    print(f"\n[*] جاري معالجة قاعدة البيانات: {csv_file} ...")
    try:
        # 1. قراءة البيانات
        df = pd.read_csv(csv_file)
        print(f"  - تم العثور على {len(df)} جملة.")

        # 2. بناء محول النصوص بناءً على اللغة
        if is_arabic:
            vectorizer = TfidfVectorizer(ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b')
        else:
            vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english')

        X = vectorizer.fit_transform(df['text'])
        y = df['label']

        # 3. فحص الدقة (اختبار 20% من البيانات)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = MultinomialNB(alpha=0.1)
        model.fit(X_train, y_train)
        
        acc = accuracy_score(y_test, model.predict(X_test))
        print(f"  - مستوى الدقة (Accuracy): {acc * 100:.2f}%")

        # 4. التدريب النهائي والحفظ
        model.fit(X, y) # التدريب على 100% من البيانات للحصول على أقصى ذكاء
        joblib.dump(model, model_name)
        joblib.dump(vectorizer, vectorizer_name)
        
        print(f"  ✅ تم توليد وحفظ النماذج ({model_name}) بنجاح.")

    except FileNotFoundError:
        print(f"  ❌ خطأ: لم يتم العثور على ملف {csv_file} في المجلد.")
    except Exception as e:
        print(f"  ❌ خطأ غير متوقع: {e}")

# تنفيذ التدريب للغة العربية
train_language_model('dataset.csv', 'arabic_phishing_model.pkl', 'arabic_tfidf_vectorizer.pkl', is_arabic=True)

# تنفيذ التدريب للغة الإنجليزية
train_language_model('dataset_en.csv', 'phishing_model.pkl', 'tfidf_vectorizer.pkl', is_arabic=False)

print("\n" + "="*50)
print("🎯 تمت عملية التدريب الشاملة بنجاح! السيرفر جاهز للعمل.")
print("="*50)