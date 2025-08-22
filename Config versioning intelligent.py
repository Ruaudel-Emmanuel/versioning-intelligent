# requirements.txt
watchdog==3.0.0
requests==2.31.0

# setup.py
from setuptools import setup, find_packages

setup(
    name="smart-versioning-system",
    version="1.0.0",
    description="Système de versioning intelligent avec surveillance automatique",
    packages=find_packages(),
    install_requires=[
        "watchdog>=3.0.0",
        "requests>=2.31.0",
    ],
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'smart-versioning=smart_versioning:main',
        ],
    },
)

# versioning_config.json (exemple)
{
  "local_repo_path": ".",
  "github_token": "ghp_your_github_token_here",
  "github_username": "your_username",
  "github_repo": "your_repo_name",
  "auto_commit": true,
  "auto_push": false,
  "commit_interval": 300,
  "ignored_patterns": [
    ".git/",
    "__pycache__/",
    ".pyc",
    ".tmp",
    ".log",
    "node_modules/",
    ".env",
    "*.sqlite"
  ]
}

# install.sh (script d'installation Linux/Mac)
#!/bin/bash

echo "🚀 Installation du Système de Versioning Intelligent"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

# Créer un environnement virtuel
echo "📦 Création de l'environnement virtuel..."
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
echo "⬇️ Installation des dépendances..."
pip install watchdog requests

# Rendre le script exécutable
chmod +x smart_versioning.py

echo "✅ Installation terminée!"
echo ""
echo "Usage:"
echo "  source venv/bin/activate"
echo "  python smart_versioning.py start   # Démarre la surveillance"
echo "  python smart_versioning.py sync    # Synchronisation manuelle"
echo "  python smart_versioning.py status  # Affiche l'état"

# install.bat (script d'installation Windows)
@echo off
echo 🚀 Installation du Système de Versioning Intelligent

REM Vérifier Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python n'est pas installé
    pause
    exit /b 1
)

REM Créer un environnement virtuel
echo 📦 Création de l'environnement virtuel...
python -m venv venv
call venv\Scripts\activate.bat

REM Installer les dépendances
echo ⬇️ Installation des dépendances...
pip install watchdog requests

echo ✅ Installation terminée!
echo.
echo Usage:
echo   venv\Scripts\activate.bat
echo   python smart_versioning.py start   # Démarre la surveillance
echo   python smart_versioning.py sync    # Synchronisation manuelle
echo   python smart_versioning.py status  # Affiche l'état
pause