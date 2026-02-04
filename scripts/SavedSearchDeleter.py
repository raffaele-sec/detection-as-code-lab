import os
import sys
import urllib3
import requests
from sigma.collection import SigmaCollection
import subprocess
import yaml
from sigma.exceptions import SigmaCollectionError

urllib3.disable_warnings()


SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")

if not SPLUNK_HOST:
    print("URL di Splunk non trovato")
    sys.exit(1)
elif not SPLUNK_TOKEN:
    print("Token di autenticazione Splunk non trovato")
    sys.exit(1)

headers = {
        "Authorization" : f"Bearer {SPLUNK_TOKEN}"
    }

rules_content_list=[]

try:
    files_deleted=subprocess.check_output("git diff --name-only --diff-filter=D HEAD~1 HEAD", shell=True, text=True).strip()
    if files_deleted:

        #lancia il comando "git diff" per vedere i file eliminati, confrontando il commit attuale con quello precedente
        rules_deleted= files_deleted.split('\n')
        #crea una lista di file eliminati da poter iterare tramite "split" + newline

        #controlliamo riga per riga i file eliminati
        for path_rule in rules_deleted:
            if ".yml" in path_rule: #se il file eliminato è una sigma rule, quindi c'è l'estensione yaml

                deleted_rules_content=subprocess.check_output(f"git show HEAD^:{path_rule}", shell=True, text=True).strip()
                #si lancia il comando git show per mostrare il contenuto della sigma rule eliminata

                yaml_converted_content=yaml.safe_load(deleted_rules_content)
                #si converte in yaml il contenuto e poi lo si aggiunge alla lista, per prepararla alla lettura da parte di SigmaCollection
                #diventando così una lista di dizionari
                rules_content_list.append(yaml_converted_content)
    else:
        print("Nessuna sigma rule eliminata. Non bisogna eliminare nulla su splunk")
        sys.exit(0)

except subprocess.CalledProcessError as e:
    print(f"Errore {e}")
    sys.exit(1)

try:
    collected_rules=SigmaCollection.from_dicts(rules_content_list)


    for rules in collected_rules.rules:

        splunk_url=f"{SPLUNK_HOST}/servicesNS/nobody/search/saved/searches/{rules.title}"
        #imposto il path della saved search su splunk con il titolo della regola da eliminare
        #così facendo posso fare la DELETE verso l'api di splunk

        try:
            req_api=requests.delete(url=splunk_url, headers=headers, verify=False, timeout=10)
            if req_api.status_code == 200:
                print(f"La regola {rules.title} è stata eliminata con successo")
            elif req_api.status_code == 404:
                print(f"La regola {rules.title} non è presente o è già stata eliminata")
            else:
                print(f"Errore {req_api.status_code}: {req_api.text}")
                sys.exit(1)

        except requests.RequestException as err: #RequestException cattura tutti i tipi di errori, come timeout e connectionerror
            print(err)

except SigmaCollectionError: #gestione errori di collection importata da sigma.exceptions
    print("Errore di lettura delle regole da SigmaCollection")
    sys.exit(1)
