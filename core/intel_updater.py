import sqlite3
import requests
import os
from rich.console import Console
from datetime import datetime

console = Console()

class IntelUpdater:
    def __init__(self, db_path="data/threat_intel.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

        self.sources = {
            "Firehol_L1": "https://iplists.firehol.org/files/firehol_level1.netset",
            "Emerging_Threats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
            "GreenSnow": "https://blocklist.greensnow.co/greensnow.txt",
            "BruteForceBlocker": "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
        }

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS local_blacklist (
                    ip_address TEXT PRIMARY KEY,
                    source TEXT,
                    score INTEGER,
                    added_at DATETIME
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON local_blacklist (ip_address)")

    def update_all(self):
        """Mengambil data dari semua sumber dan membersihkan formatnya."""
        total_new_ips = 0
        console.print("[bold blue]🚀 Memulai Agregasi Threat Intelligence...[/bold blue]")

        for name, url in self.sources.items():
            try:
                console.print(f"[*] Mengunduh dari [cyan]{name}[/cyan]...")
                res = requests.get(url, timeout=15)
                if res.status_code == 200:
                    clean_ips = []
                    for line in res.text.splitlines():
                        line = line.strip()
                        # Lewati baris kosong atau komentar penuh
                        if not line or line.startswith(("#", ";")):
                            continue
                        
                        # Ambil bagian sebelum komentar (# atau ;) dan ambil kata pertama (IP)
                        ip_part = line.split('#')[0].split(';')[0].split()[0].strip()
                        if ip_part:
                            clean_ips.append(ip_part)
                    
                    added = self._save_to_db(clean_ips, name)
                    total_new_ips += added
                    console.print(f"    [green]✓ Berhasil memproses {len(clean_ips)} IP ({added} baru).[/green]")
                else:
                    console.print(f"    [red]✗ Gagal (Status: {res.status_code})[/red]")
            except Exception as e:
                console.print(f"    [red]✗ Error saat memproses {name}: {str(e)}[/red]")

        console.print(f"\n[bold green]✅ Selesai! Total IP di database: {self._get_total_count()}[/bold green]")

    def _save_to_db(self, ip_list, source):
        now = datetime.now().isoformat()
        added_count = 0
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            data = [(ip, source, 100, now) for ip in ip_list]
            cursor.executemany(
                "INSERT OR IGNORE INTO local_blacklist (ip_address, source, score, added_at) VALUES (?, ?, ?, ?)",
                data
            )
            added_count = cursor.rowcount
            conn.commit()
        return added_count

    def _get_total_count(self):
        with sqlite3.connect(self.db_path) as conn:
            res = conn.execute("SELECT COUNT(*) FROM local_blacklist").fetchone()
            return res[0]