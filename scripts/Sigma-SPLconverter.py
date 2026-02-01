import os
import sys
import urllib3
import requests
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.exceptions import SigmaCollectionError, SigmaConversionError

#per disabilitare warning SSL, perchè la porta 8089 usata per la gestione delle API di splunk 
#abilita di default HTTPS.
urllib3.disable_warnings()



#prendo i valori dell'url e del token dalle variabili d'ambiente del sistema (nel caso di git, dai secrets)
#ricordarsi di impostare l'url come https e non http per le API!
SPLUNK_HOST = os.environ.get("SPLUNK_HOST")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN")

if not SPLUNK_HOST:
    print("URL di Splunk non trovato")
    #permette a git di terminare il programma con un errore
    sys.exit(1)
elif not SPLUNK_TOKEN:
    print("Token di autenticazione Splunk non trovato")
    sys.exit(1)




#Gli argument della funzione verranno presi dalle regole convertite
def deploy_rule(name, query, description):

    #creo l'url aggiungendo il path dell'API delle ricerche salvate per gli alert di Splunk
    #rispetto al path trovato nella doc di splunk, bisogna aggiungere "servicesNS/nobody/search" per far si
    #che la rule diventi visibile a tutti e non solo all'utente di default
    splunk_url=f"{SPLUNK_HOST}/servicesNS/nobody/search/saved/searches"

    #creazione degli header per passare il token, gli esempi sono della documentazione di Splunk
    #sezione "Use authentication tokens"
    headers = {
        "Authorization" : f"Bearer {SPLUNK_TOKEN}"
    }

    #preparo il payload, ossia i campi che popoleranno la creazione dell'alert su Splunk.
    payload = {
        # --- PARAMETRI PER CREARE UN REPORT
        "name" : name,
        "search" : query,
        "description" : description,
        "is_scheduled" : "1",
        "cron_schedule" : "*/5 * * * *",
        # --- PARAMETRI PER TRASFORMARLO IN ALLARME
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",
        "alert.severity": "4"
        }
    
    #il dizionario contenente i campi per la creazione dell'alert vengono passati a "data"
    #se la creazione va a buon fine viene restituito lo status code 201
    #se la rule è già esistente, viene generato lo status code 409
    post_api = requests.post(url=splunk_url, headers=headers, verify=False, data=payload)
    

    if post_api.status_code == 201:
        print("La regola è stata creata con successo!")

    #Se restituisce status code 409 vuol dire che la rule c'è già, quindi fa l'update.
    elif post_api.status_code == 409:
        print("La regola è già presente. Verrà effettuato l'update!")
        
        #devo quindi "contattare" l'url con il nome della regola alla fine
        splunk_url_update=f"{splunk_url}/{name}"
        
        #per l'update della regola devo eliminare il campo "name", sennò da errore 409
        payload = {
        "search" : query,
        "description" : description,
        "is_scheduled" : "1",
        "cron_schedule" : "*/5 * * * *",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",
        "alert.severity": "4"
        }
        post_update_api = requests.post(url=splunk_url_update, headers=headers, verify=False, data=payload)
        if post_update_api.status_code == 200:
            print("Update della regola effettuato con successo.")
        else:
            print("Errore nell'update della regola.")
            sys.exit(1)
        


rules_path="./rules/"

#importo le regole Sigma dal path "rules" massivamente. SigmaColleciton permette la lettura dei file YAML
#collection_rules diventa un oggetto che contiene una lista di regola Sigma
try:
    collection_rules=SigmaCollection.load_ruleset([rules_path])

    #si imposta il backend per la conversione
    backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
except SigmaCollectionError: #gestione errori di collection importata da sigma.exceptions
    print("Errore di lettura delle regole da SigmaCollection")


#la proprietà "rules" di SigmaCollection permette di accedere alle singole regole nella collection e ai singoli campi della rule Sigma
#Questo serve per estrarre i campi da passare al payload della POST verso l'API di Splunk per creare l'alert
#questo ciclo for itera nella lista delle regole
for rule in collection_rules.rules:
    rule_name=rule.title
    rule_description=rule.description

    #converto la singola regola nell'iterazione. backend.convert() accetta la collection, mentre convert_rule() accetta una singola regola.
    try:
        converted_rule = backend.convert_rule(rule)

        #invio i campi estratti regola per regola verso splunk tramite la funziona creata
        #perchè "converted_rule[0]"? perchè l afunzione backend.convert_rule potrebbe restituire più query da un'unica regola SIGMA, quindi ne teniamo 1.
        deploy_rule(rule_name, converted_rule[0], rule_description)
    except SigmaConversionError: #gestione errori di conversione importata da sigma.exceptions
        continue
