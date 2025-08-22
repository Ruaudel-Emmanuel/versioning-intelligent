#!/usr/bin/env python3
"""
Système de Versioning Intelligent
Automatise la synchronisation Git avec analyse intelligente des changements
"""

import os
import sys
import time
import json
import subprocess
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import threading
from queue import Queue


@dataclass
class FileChange:
    """Représente un changement de fichier"""
    path: str
    change_type: str  # 'modified', 'created', 'deleted'
    timestamp: datetime
    content_hash: Optional[str] = None


class GitHubAPI:
    """Interface pour l'API GitHub"""
    
    def __init__(self, token: str, username: str, repo: str):
        self.token = token
        self.username = username
        self.repo = repo
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = f'https://api.github.com/repos/{username}/{repo}'
    
    def get_repo_info(self) -> Dict:
        """Récupère les informations du repository"""
        response = requests.get(self.base_url, headers=self.headers)
        return response.json() if response.status_code == 200 else {}
    
    def create_issue(self, title: str, body: str) -> Dict:
        """Crée une issue pour signaler des problèmes"""
        data = {'title': title, 'body': body}
        response = requests.post(f'{self.base_url}/issues', 
                               headers=self.headers, json=data)
        return response.json() if response.status_code == 201 else {}


class CodeAnalyzer:
    """Analyseur intelligent de code"""
    
    def __init__(self):
        self.sensitive_patterns = [
            r'password\s*=\s*["\'].*["\']',
            r'api[_-]?key\s*=\s*["\'].*["\']',
            r'secret\s*=\s*["\'].*["\']',
            r'token\s*=\s*["\'].*["\']',
            r'mysql://.*:.*@',
            r'postgres://.*:.*@'
        ]
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyse un fichier pour détecter les problèmes et le type de changement"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {'error': str(e)}
        
        analysis = {
            'file_type': self._get_file_type(file_path),
            'line_count': len(content.splitlines()),
            'has_sensitive_data': self._check_sensitive_data(content),
            'complexity': self._estimate_complexity(content),
            'suggested_message': self._generate_commit_message(file_path, content)
        }
        
        return analysis
    
    def _get_file_type(self, file_path: str) -> str:
        """Détermine le type de fichier"""
        ext = Path(file_path).suffix.lower()
        type_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.html': 'HTML',
            '.css': 'CSS',
            '.md': 'Markdown',
            '.json': 'JSON',
            '.yml': 'YAML',
            '.yaml': 'YAML',
            '.txt': 'Text'
        }
        return type_map.get(ext, 'Unknown')
    
    def _check_sensitive_data(self, content: str) -> bool:
        """Vérifie la présence de données sensibles"""
        content_lower = content.lower()
        for pattern in self.sensitive_patterns:
            if re.search(pattern, content_lower):
                return True
        return False
    
    def _estimate_complexity(self, content: str) -> str:
        """Estime la complexité du code"""
        lines = len(content.splitlines())
        if lines < 50:
            return 'Simple'
        elif lines < 200:
            return 'Moderate'
        else:
            return 'Complex'
    
    def _generate_commit_message(self, file_path: str, content: str) -> str:
        """Génère un message de commit intelligent"""
        filename = Path(file_path).name
        file_type = self._get_file_type(file_path)
        
        # Détection des mots-clés dans le contenu
        keywords = self._extract_keywords(content)
        
        if 'class ' in content and file_type == 'Python':
            return f"feat: add new class implementation in {filename}"
        elif 'def ' in content and file_type == 'Python':
            return f"feat: implement new functions in {filename}"
        elif 'fix' in keywords or 'bug' in keywords:
            return f"fix: resolve issues in {filename}"
        elif 'update' in keywords or 'modify' in keywords:
            return f"update: modify {filename}"
        else:
            return f"chore: update {filename}"
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extrait les mots-clés du contenu"""
        common_keywords = ['fix', 'bug', 'update', 'add', 'remove', 'modify']
        content_lower = content.lower()
        return [kw for kw in common_keywords if kw in content_lower]


class GitManager:
    """Gestionnaire Git local"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.ensure_git_repo()
    
    def ensure_git_repo(self):
        """S'assure que le dossier est un repository Git"""
        git_dir = self.repo_path / '.git'
        if not git_dir.exists():
            self.run_git_command(['init'])
            print(f"Repository Git initialisé dans {self.repo_path}")
    
    def run_git_command(self, cmd: List[str]) -> Tuple[bool, str]:
        """Execute une commande Git"""
        try:
            result = subprocess.run(
                ['git'] + cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout or result.stderr
        except Exception as e:
            return False, str(e)
    
    def add_file(self, file_path: str) -> bool:
        """Ajoute un fichier au staging"""
        success, _ = self.run_git_command(['add', file_path])
        return success
    
    def commit(self, message: str) -> bool:
        """Effectue un commit"""
        success, _ = self.run_git_command(['commit', '-m', message])
        return success
    
    def push(self, branch: str = 'main') -> bool:
        """Pousse vers le repository distant"""
        success, _ = self.run_git_command(['push', 'origin', branch])
        return success
    
    def create_branch(self, branch_name: str) -> bool:
        """Crée une nouvelle branche"""
        success, _ = self.run_git_command(['checkout', '-b', branch_name])
        return success
    
    def get_status(self) -> str:
        """Récupère le status Git"""
        success, output = self.run_git_command(['status', '--porcelain'])
        return output if success else ""


class FileWatcher(FileSystemEventHandler):
    """Surveillant de fichiers avec intelligence"""
    
    def __init__(self, change_queue: Queue, ignored_patterns: List[str] = None):
        self.change_queue = change_queue
        self.ignored_patterns = ignored_patterns or [
            '.git/', '__pycache__/', '.pyc', '.tmp', '.log'
        ]
        self.file_hashes = {}
    
    def should_ignore(self, file_path: str) -> bool:
        """Vérifie si le fichier doit être ignoré"""
        for pattern in self.ignored_patterns:
            if pattern in file_path:
                return True
        return False
    
    def get_file_hash(self, file_path: str) -> str:
        """Calcule le hash d'un fichier"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return ""
    
    def on_modified(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            current_hash = self.get_file_hash(event.src_path)
            previous_hash = self.file_hashes.get(event.src_path)
            
            if current_hash != previous_hash:
                self.file_hashes[event.src_path] = current_hash
                change = FileChange(
                    path=event.src_path,
                    change_type='modified',
                    timestamp=datetime.now(),
                    content_hash=current_hash
                )
                self.change_queue.put(change)
    
    def on_created(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            change = FileChange(
                path=event.src_path,
                change_type='created',
                timestamp=datetime.now()
            )
            self.change_queue.put(change)
    
    def on_deleted(self, event):
        if not event.is_directory and not self.should_ignore(event.src_path):
            change = FileChange(
                path=event.src_path,
                change_type='deleted',
                timestamp=datetime.now()
            )
            self.change_queue.put(change)


class SmartVersioningSystem:
    """Système principal de versioning intelligent"""
    
    def __init__(self, config_path: str = "versioning_config.json"):
        self.config = self.load_config(config_path)
        self.change_queue = Queue()
        self.analyzer = CodeAnalyzer()
        self.git_manager = GitManager(self.config['local_repo_path'])
        
        if self.config.get('github_token'):
            self.github_api = GitHubAPI(
                self.config['github_token'],
                self.config['github_username'],
                self.config['github_repo']
            )
        else:
            self.github_api = None
        
        self.observer = Observer()
        self.file_watcher = FileWatcher(self.change_queue, self.config.get('ignored_patterns'))
        self.running = False
    
    def load_config(self, config_path: str) -> Dict:
        """Charge la configuration"""
        default_config = {
            'local_repo_path': '.',
            'github_token': '',
            'github_username': '',
            'github_repo': '',
            'auto_commit': True,
            'auto_push': False,
            'commit_interval': 300,  # 5 minutes
            'ignored_patterns': ['.git/', '__pycache__/', '.pyc', '.tmp', '.log']
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                print(f"Erreur lors du chargement de la config: {e}")
        else:
            # Créer le fichier de config par défaut
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Fichier de configuration créé: {config_path}")
        
        return default_config
    
    def start_monitoring(self):
        """Démarre la surveillance des fichiers"""
        self.running = True
        self.observer.schedule(
            self.file_watcher,
            self.config['local_repo_path'],
            recursive=True
        )
        self.observer.start()
        
        # Démarrer le thread de traitement
        processing_thread = threading.Thread(target=self.process_changes)
        processing_thread.daemon = True
        processing_thread.start()
        
        print(f"🚀 Surveillance démarrée sur: {self.config['local_repo_path']}")
        print("Appuyez sur Ctrl+C pour arrêter...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Arrête la surveillance"""
        self.running = False
        self.observer.stop()
        self.observer.join()
        print("\n📴 Surveillance arrêtée")
    
    def process_changes(self):
        """Traite les changements détectés"""
        pending_changes = []
        last_commit_time = time.time()
        
        while self.running:
            try:
                # Récupérer les changements dans la queue
                if not self.change_queue.empty():
                    change = self.change_queue.get(timeout=1)
                    pending_changes.append(change)
                    print(f"📝 Changement détecté: {change.path} ({change.change_type})")
                
                # Commit périodique si auto_commit est activé
                current_time = time.time()
                if (pending_changes and 
                    self.config['auto_commit'] and 
                    current_time - last_commit_time >= self.config['commit_interval']):
                    
                    self.process_pending_changes(pending_changes)
                    pending_changes.clear()
                    last_commit_time = current_time
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Erreur dans le traitement: {e}")
                time.sleep(5)
    
    def process_pending_changes(self, changes: List[FileChange]):
        """Traite un lot de changements"""
        if not changes:
            return
        
        print(f"🔄 Traitement de {len(changes)} changement(s)...")
        
        # Analyser les changements
        analysis_results = []
        for change in changes:
            if change.change_type != 'deleted' and os.path.exists(change.path):
                analysis = self.analyzer.analyze_file(change.path)
                analysis_results.append((change, analysis))
        
        # Vérifier les données sensibles
        sensitive_files = [
            (change, analysis) for change, analysis in analysis_results
            if analysis.get('has_sensitive_data', False)
        ]
        
        if sensitive_files:
            print("⚠️  Données sensibles détectées dans:")
            for change, analysis in sensitive_files:
                print(f"   - {change.path}")
            
            if self.github_api:
                self.github_api.create_issue(
                    "Données sensibles détectées",
                    f"Les fichiers suivants contiennent potentiellement des données sensibles:\n" +
                    "\n".join([f"- {change.path}" for change, _ in sensitive_files])
                )
            return
        
        # Ajouter et commiter les fichiers
        success_count = 0
        for change in changes:
            if change.change_type != 'deleted':
                relative_path = os.path.relpath(change.path, self.config['local_repo_path'])
                if self.git_manager.add_file(relative_path):
                    success_count += 1
        
        if success_count > 0:
            # Générer un message de commit intelligent
            commit_message = self.generate_batch_commit_message(changes, analysis_results)
            
            if self.git_manager.commit(commit_message):
                print(f"✅ Commit réalisé: {commit_message}")
                
                # Push automatique si activé
                if self.config['auto_push'] and self.github_api:
                    if self.git_manager.push():
                        print("📤 Push vers GitHub réussi")
                    else:
                        print("❌ Échec du push vers GitHub")
            else:
                print("❌ Échec du commit")
    
    def generate_batch_commit_message(self, changes: List[FileChange], 
                                    analysis_results: List[Tuple]) -> str:
        """Génère un message de commit pour un lot de changements"""
        if len(changes) == 1:
            change = changes[0]
            for change_item, analysis in analysis_results:
                if change_item.path == change.path:
                    return analysis.get('suggested_message', f"update: {Path(change.path).name}")
            return f"{change.change_type}: {Path(change.path).name}"
        
        # Multiple files
        file_types = set()
        for change, analysis in analysis_results:
            file_types.add(analysis.get('file_type', 'Unknown'))
        
        type_str = ', '.join(file_types) if file_types else 'files'
        return f"feat: update multiple {type_str} ({len(changes)} files)"
    
    def manual_sync(self):
        """Synchronisation manuelle"""
        print("🔄 Synchronisation manuelle en cours...")
        
        status = self.git_manager.get_status()
        if not status.strip():
            print("✅ Aucun changement à synchroniser")
            return
        
        print("📋 Changements détectés:")
        print(status)
        
        # Analyser tous les fichiers modifiés
        modified_files = []
        for line in status.strip().split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    file_path = parts[1]
                    full_path = os.path.join(self.config['local_repo_path'], file_path)
                    if os.path.exists(full_path):
                        modified_files.append(full_path)
        
        if not modified_files:
            return
        
        # Traiter comme des changements pending
        changes = [
            FileChange(
                path=f,
                change_type='modified',
                timestamp=datetime.now()
            ) for f in modified_files
        ]
        
        self.process_pending_changes(changes)
    
    def show_status(self):
        """Affiche le statut du système"""
        print("\n📊 État du système de versioning intelligent")
        print("=" * 50)
        print(f"📁 Repository local: {self.config['local_repo_path']}")
        print(f"🤖 Auto-commit: {'✅' if self.config['auto_commit'] else '❌'}")
        print(f"📤 Auto-push: {'✅' if self.config['auto_push'] else '❌'}")
        print(f"⏱️  Intervalle commit: {self.config['commit_interval']}s")
        
        if self.github_api:
            repo_info = self.github_api.get_repo_info()
            if repo_info:
                print(f"🐙 GitHub: {repo_info.get('full_name', 'N/A')}")
        
        status = self.git_manager.get_status()
        if status.strip():
            print("\n📋 Changements en attente:")
            print(status)
        else:
            print("\n✅ Aucun changement en attente")


def main():
    """Fonction principale"""
    if len(sys.argv) < 2:
        print("Usage: python smart_versioning.py [start|sync|status]")
        print("  start  - Démarre la surveillance automatique")
        print("  sync   - Synchronisation manuelle")
        print("  status - Affiche l'état du système")
        return
    
    command = sys.argv[1].lower()
    system = SmartVersioningSystem()
    
    if command == 'start':
        system.start_monitoring()
    elif command == 'sync':
        system.manual_sync()
    elif command == 'status':
        system.show_status()
    else:
        print(f"Commande inconnue: {command}")


if __name__ == "__main__":
    main()