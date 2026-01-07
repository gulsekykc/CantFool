
#KUR
bash
# Repoyu klonla
git clone https://github.com/kullaniciadi/cantfool.git
cd cantfool

# Sanal ortam oluştur
python -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows

#yükle
pip install -r requirements.txt

# Flask API başlat (ÇALIŞTIR)
python app.py
