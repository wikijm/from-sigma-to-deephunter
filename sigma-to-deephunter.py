import os
import re
import json
import yaml
import requests
import zipfile

# Configuration
GITHUB_REPO_URL = 'https://github.com/wikijm/ConvertSigmaRepo2SentinelOnePQ/archive/refs/heads/main.zip'
LOCAL_REPO_PATH = 'local_repo'
QUERY_JSON_PATH = 'query.json'
ZIP_FILE_PATH = 'repo.zip'
ERRORS_LOG_PATH = 'errors.log'

# Fonction pour télécharger et extraire le dépôt GitHub
def download_and_extract_repo(repo_url, zip_path, extract_path):
    try:
        response = requests.get(repo_url)
        response.raise_for_status()

        with open(zip_path, 'wb') as zip_file:
            zip_file.write(response.content)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)

        # Supprimer le fichier zip après extraction
        os.remove(zip_path)
        return True
    except requests.RequestException as e:
        log_error(f"Erreur lors du téléchargement du dépôt : {e}")
        return False
    except zipfile.BadZipFile as e:
        log_error(f"Erreur lors de l'extraction du fichier zip : {e}")
        return False

# Fonction pour obtenir les fichiers .md
def get_md_files(local_path):
    md_files = []
    for root, _, files in os.walk(local_path):
        for file in files:
            if file.endswith('.md') and file != 'README.md':
                md_files.append(os.path.join(root, file))
    return md_files

# Fonction pour extraire la requête Powerquery et la règle SIGMA
def extract_info(content):
    lines = content.split('\n')
    powerquery = lines[2].strip() if len(lines) > 2 else ''
    sigma_rule = re.search(r'```yaml(.*?)```', content, re.DOTALL)
    sigma_rule = sigma_rule.group(1).strip() if sigma_rule else ''

    return powerquery, sigma_rule

# Fonction pour extraire les attributs de la règle SIGMA
def parse_sigma_rule(sigma_rule):
    try:
        sigma_data = yaml.safe_load(sigma_rule)
        if sigma_data is None:
            raise ValueError("Contenu YAML invalide ou vide")

        description = sigma_data.get('description', '')
        title = sigma_data.get('title', '')
        tags = sigma_data.get('tags', [])

        mitre_techniques = [tag.split('.')[1] for tag in tags if tag.startswith('attack.t')]

        return description, title, mitre_techniques
    except yaml.YAMLError as e:
        log_error(f"Erreur lors de l'analyse de la règle SIGMA : {e}")
        return '', '', []
    except ValueError as e:
        log_error(f"Erreur de contenu YAML : {e}")
        return '', '', []

# Fonction pour créer ou mettre à jour le fichier query.json
def update_query_json(entries):
    if os.path.exists(QUERY_JSON_PATH):
        with open(QUERY_JSON_PATH, 'r') as json_file:
            existing_entries = json.load(json_file)
            entries.extend(existing_entries)

    with open(QUERY_JSON_PATH, 'w') as json_file:
        json.dump(entries, json_file, indent=4)

# Fonction pour enregistrer les erreurs dans un fichier log
def log_error(message):
    with open(ERRORS_LOG_PATH, 'a') as log_file:
        log_file.write(message + '\n')

# Main
if __name__ == "__main__":
    if download_and_extract_repo(GITHUB_REPO_URL, ZIP_FILE_PATH, LOCAL_REPO_PATH):
        md_files = get_md_files(os.path.join(LOCAL_REPO_PATH, 'ConvertSigmaRepo2SentinelOnePQ-main'))
        pk = 1
        query_entries = []

        for file_path in md_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                # Extraire les informations
                powerquery, sigma_rule = extract_info(content)
                description, title, mitre_techniques = parse_sigma_rule(sigma_rule)

                # Créer l'entrée query
                query_data = {
                    "fields": {
                        "actors": [],
                        "anomaly_threshold_count": 2,
                        "anomaly_threshold_endpoints": 2,
                        "columns": "| columns event.time, event.type, site.name, agent.uuid, src.process.storyline.id, src.process.user, src.process.uid, src.process.cmdline, src.ip.address, src.port.number, dst.ip.address, dst.port.number, src.process.parent.cmdline, tgt.process.cmdline",
                        "confidence": 2,
                        "description": description,
                        "dynamic_query": False,
                        "emulation_validation": "",
                        "mitre_techniques": mitre_techniques,
                        "name": title,
                        "notes": "- To move around freely without attracting too much attention, attackers often use reliable software (one of the favorites is psexec) that looks normal in an enterprise environment.\r\n- Use the following aggregate to easily group by endpoint: `| group array_agg_distinct(dst.ip.address) by endpoint.name, src.process.cmdline`",
                        "pub_date": "2023-03-16T08:02:46.204Z",
                        "pub_status": "DIST",
                        "query": powerquery,
                        "references": "https://theitbros.com/using-psexec-to-run-commands-remotely/, https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/",
                        "relevance": 3,
                        "run_daily": True,
                        "star_rule": False,
                        "tags": ["From SIGMA"],
                        "target_os": [1],
                        "threats": [],
                        "update_date": "2024-11-26T08:03:25.622Z",
                        "vulnerabilities": [],
                        "weighted_relevance": 1.5
                    },
                    "model": "qm.query",
                    "pk": pk
                }

                query_entries.append(query_data)
                pk += 1
            except Exception as e:
                log_error(f"Erreur lors du traitement du fichier {file_path} : {e}")

        # Mettre à jour le fichier query.json
        update_query_json(query_entries)
