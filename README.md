# Basic-Django-template

# Phonebox

### 1. Clone the Repository

```bash
git clone git clone git@github.com:dilawaizkhan08/PiLIMS.git
cd PiLIMS
```
### 2. Create & Activate a Virtual Environment

#### On macos
```bash
python3 -m venv venv
source venv/bin/activate
```

#### On windows
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```


### 4. Run migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

#### 5. Run the Development Server
```bash
python manage.py runserver
```