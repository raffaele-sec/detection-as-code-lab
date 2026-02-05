import os
import sys
import urllib3
import requests
from sigma.collection import SigmaCollection
import subprocess
import yaml
from sigma.exceptions import SigmaCollectionError


#per disabilitare warning SSL, perchè la porta 8089 usata per la gestione delle API di splunk 
#abilita di default HTTPS.
urllib3.disable_warnings()


#prendo i valori dell'url e del token dalle variabili d'ambiente del sistema (nel caso di git, dai secrets)
#ricordarsi di impostare l'url come https e non http per le API!
SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")

if not SPLUNK_HOST:
    print("URL di Splunk non trovato")
    sys.exit(1) #permette a git di terminare il programma con un errore
elif not SPLUNK_TOKEN:
    print("Token di autenticazione Splunk non trovato")
    sys.exit(1)


#creazione degli header per passare il token di autenticazione per l'API di Splunk, gli esempi sono della documentazione di Splunk
#sezione "Use authentication tokens"
headers = {
        "Authorization" : f"Bearer {SPLUNK_TOKEN}"
    }


rules_content_list=[]


try:
    #lancia il comando "git diff" per vedere i file eliminati, confrontando il commit attuale con quello precedente
    files_deleted=subprocess.check_output("git diff --name-only --diff-filter=D HEAD~1 HEAD", shell=True, text=True).strip()
    if files_deleted: #se l'output del comando è popolato, quindi risultano file eliminati

        rules_deleted= files_deleted.split('\n')
        #dall'output del comando, che è "text", creo una LISTA i cui singoli elementi saranno i path dei file eliminati

        #itero ogni elemento della lista, quindi ogni path dei file eliminati
        for path_rule in rules_deleted:
            if ".yml" in path_rule: #se il file eliminato è di tipo YAML, quindi è una sigma rule

                deleted_rules_content=subprocess.check_output(f"git show HEAD^:{path_rule}", shell=True, text=True).strip()
                #si lancia il comando git show per mostrare il contenuto della sigma rule eliminata e assegnarlo alla variabile "deleted_rules_content"
                #il formato sarà "text"

                yaml_converted_content=yaml.safe_load(deleted_rules_content)
                #si converte la variabile "deleted_rules_content" di tipo "text" in yaml
                #questo per poter accedere successivamente al "nome" della regola, che è il valore da passare alla richiesta HTTP verso l'API di Splunk
                rules_content_list.append(yaml_converted_content)
                #e poi si aggiunge la regola convertita in YAML alla lista, creando una LISTA di DIZIONARI
                #così facendo possiamo usare efficacemente SigmaCollection
    else:
        print("Nessuna sigma rule eliminata. Non bisogna eliminare nulla su splunk")
        sys.exit(0)
        #termina il programma con successo, perchè non rileva nessun elimnazione.
        #così il job del workflow di github termina, ma senza generare errore.

except subprocess.CalledProcessError as e:
    print(f"Errore {e}")
    sys.exit(1)

try:
    collected_rules=SigmaCollection.from_dicts(rules_content_list)
    #carica tutte le rule nella lista di dizionari nella variabile "collected_rules", creando un oggetto


    for rules in collected_rules.rules:
        #".rules" permette di iterare tutte le sigma rule presente nell'oggetto "collected_rules"
        #è particolarmente efficace perchè permette di leggere/accedere ogni campo della sigma rule in maniera semplice

        splunk_url=f"{SPLUNK_HOST}/servicesNS/nobody/search/saved/searches/{rules.title}"
        #"rules.title" usa la funzione di pysigma ".title" per accedere al campo "title:" della Sigma rule
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
