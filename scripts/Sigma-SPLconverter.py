import os
import sys
import urllib3
import requests
import urllib
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline #per mappare gli EventID di sysmon nella query SPL https://github.com/SigmaHQ/pySigma-pipeline-sysmon
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
    sys.exit(1) #permette a git di terminare il programma con un errore
elif not SPLUNK_TOKEN:
    print("Token di autenticazione Splunk non trovato")
    sys.exit(1)




#Gli argument della funzione verranno presi dalle regole Sigma dopo la collection
def deploy_rule(name, query, description):

    #creo l'url aggiungendo il path dell'API delle ricerche salvate per gli alert di Splunk
    #rispetto al path trovato nella doc di splunk, bisogna aggiungere "servicesNS/nobody/search" per far si
    #che la rule diventi visibile a tutti e non solo all'utente di default
    splunk_url=f"{SPLUNK_HOST}/servicesNS/nobody/search/saved/searches"

    #creazione degli header per passare il token di autenticazione per l'API di Splunk, gli esempi sono della documentazione di Splunk
    #sezione "Use authentication tokens"
    headers = {
        "Authorization" : f"Bearer {SPLUNK_TOKEN}"
    }

    #preparo il payload, ossia i campi che popoleranno la creazione dell'alert su Splunk. NON SERVE, adesso verranno generati report
    #non serve che venga triggerato l'allarme direttamente dalla SigmaRule-SPL
    payload = {
        # --- PARAMETRI PER CREARE UN REPORT
        "name" : name,
        "search" : query,
        "description" : description,
        "is_scheduled" : "1",
        "cron_schedule" : "*/5 * * * *",
        "dispatch.earliest_time": "-5m",
        "dispatch.latest_time": "now" 
        #indica che le query avviene è schedulata e avviene ogni 5 minuti, e vede gli eventi avvenuti fino a 5 minuti prima della ricerca

        # --- PARAMETRI PER TRASFORMARLO IN ALLARME
        #"alert_type": "number of events",
        #"alert_comparator": "greater than",
        #"alert_threshold": "0",
        #"alert.track": "1",
        #"alert.severity": "4" #con l'aggiunta del RBA, serve che vengano creati report, non allarmi.
        }
    
    #il dizionario contenente i campi per la creazione dell'alert vengono passati a "data"
    #se la creazione va a buon fine viene restituito lo status code 201
    #se la rule è già esistente, viene generato lo status code 409
    try:
        post_api = requests.post(url=splunk_url, headers=headers, verify=False, data=payload, timeout=10)
        

        if post_api.status_code == 201:
            print(f"La regola {name} è stata creata con successo!")

        #Se restituisce status code 409 vuol dire che la rule c'è già, quindi fa l'update.
        elif post_api.status_code == 409:
            print(f"La regola {name} è già presente. Verrà eseguito un check per l'update.")
            
            #devo quindi "contattare" l'url con il nome della regola alla fine
            splunk_url_update=f"{splunk_url}/{urllib.parse.quote(name)}" ###aggiunta fix per i caratteri speciali nell'url:
            #grazie a "urllib.parse.quote()" si trasforma il nome della rule in un formato sicuro per il web, per esempio:
            #"Notepad++ Updater" diventa -> "Notepad%2B%2B%20Updater"

            #voglio controllare, prima di effettuare l'update, che le query non siano uguali
            #per avere l'output in formato JSON, per poter accedere al valore della query più facilmente (come un dictionary), metto a fine url il
            #parametro "?output_mode=json"
            

            get_api=requests.get(url=f"{splunk_url_update}?output_mode=json", headers=headers, verify=False)
            if get_api.status_code == 200:
                json_api=get_api.json()

                #perchè il [0]? perchè la parte del json dopo entry (check su cyberchef) è una lista, perchè c'è una "["
                #quindi tutto il contenuto "content" e "search" del json è nel primo elemento della lista "entry"
                splunk_query=json_api["entry"][0]["content"]["search"]

                if query == splunk_query:
                    print("Update della regola non necessario.")
                else:

                
                    #per l'update della regola devo eliminare il campo "name", sennò da errore 409
                    payload = {
                    "search" : query,
                    "description" : description,
                    "is_scheduled" : "1",
                    "cron_schedule" : "*/5 * * * *",
                    "dispatch.earliest_time": "-5m",
                    "dispatch.latest_time": "now" 
                    #"alert_type": "number of events",
                    #"alert_comparator": "greater than",
                    #"alert_threshold": "0",
                    #"alert.track": "1",
                    #"alert.severity": "4" #con l'aggiunta del RBA, serve che vengano creati report, non allarmi.
                    }
                    post_update_api = requests.post(url=splunk_url_update, headers=headers, verify=False, data=payload, timeout=10)
                    if post_update_api.status_code == 200:
                        print(f"Update della regola {name} effettuato con successo.")
                    else:
                        print(f"Errore nell'update della regola {name}.")
                        #rimosso il sys.exit(1) perchè lo script deve continuare convertire/inviare le altre rules, se presenti
            else:
                print(f"Impossibile leggere la regola {get_api.status_code} : {get_api.text}")

        #else nel caso in cui lo status code della prima POST "post_api" non sia ne 201 ne 409.
        else:
            print(f"Errore nell'update della regola {name} con errore {post_api.status_code}")
    except requests.RequestException as err: #RequestException cattura tutti i tipi di errori, come timeout e connectionerror
        print(err)
        

def score_assign(level,name): #aggiunta funzione per RBA; assegna uno score in base al level della regola Sigma
    if level == "low":
        return 10
    elif level == "medium":
        return 25
    elif level == "high":
        return 50
    elif level == "critical":
        return 100
    else:
        print(f"Errore nell'associazione dello score per la regola {name}!")
        sys.exit(1)
    


rules_path="./rules/"

sysmon_fields = (
        "Computer, User, SourceUser, TargetUser, "
        "Image, SourceImage, ParentImage, TargetImage, "
        "CommandLine, ParentCommandLine, OriginalFileName, "
        "TargetFilename, TargetObject, "
        "SourceIp, DestinationIp, DestinationPort, QueryName, "
        "EventID, CallTrace, GrantedAccess, Hashes"
    ) #i campi da passare alla funzione "fields" della query splunk (post conversione)

#importo le regole Sigma dal path "rules" massivamente. SigmaColleciton permette la lettura dei file YAML
#collection_rules diventa un oggetto che contiene una lista di regola Sigma
try:
    collection_rules=SigmaCollection.load_ruleset([rules_path])

    custom_pipeline=sysmon_pipeline() + splunk_windows_pipeline()
    #serve per creare una pipeline che unisce "splunk_windows_pipeline" per convertire correttamente in SPL
    #alla "sysmon_pipeline" per mappare gli EventID in SPL. La "sysmon_pipeline" ha una priorità più bassa, quindi avviene prima
    #il processing della "sysmon_pipeline"



    #si imposta il backend per la conversione
    backend = SplunkBackend(processing_pipeline=custom_pipeline)
except SigmaCollectionError: #gestione errori di collection importata da sigma.exceptions
    print("Errore di lettura delle regole da SigmaCollection")
    sys.exit(1)

#la proprietà "rules" di SigmaCollection permette di accedere alle singole regole nella collection e ai singoli campi della rule Sigma
#Questo serve per estrarre i campi da passare al payload della POST verso l'API di Splunk per creare l'alert
#questo ciclo for itera nella lista delle regole
for rule in collection_rules.rules:
    rule_name=rule.title
    rule_description=rule.description
    rule_level=str(rule.level).lower() #aggiunta della lettura del level per implementare RBA
    #per poter essere confrontata con gli IF nella funzione è necessario che rule_level sia una stringa; il ".rules" restituisce "sigma object"
 
    rule_score=score_assign(rule_level, rule_name) #chiamo la funzione per associare il punteggio alla variabile

    add_query=(f'| eval risk_score={rule_score}, risk_object=Computer, rule_name="{rule_name}"'
               f'| fields + _time, host, risk_score, risk_object, rule_name, {sysmon_fields}' #imposto i campi da passare all'index=risk nella query
               f'| tojson output_field=_raw' #traduce tutto il log in JSON (perchè è XML)
               f'| collect index=risk' #invia tutto al nuovo indice creato (dove girerà la logica di RBA identificando i risk score).
               #tramite il collect verrà convertito il JSON in stash, quindi formato molto leggibile. (XML non lo permette)
               ) #"singoli apici" per tutta le query e "doppi apici" per {rule_name} perchè non dare errore
    #parte di query SPL che associa lo score

    #converto la singola regola nell'iterazione. backend.convert() accetta la collection, mentre convert_rule() accetta una singola regola.
    try:
        converted_rule = backend.convert_rule(rule) #converto la regola Sigma in SPL
        rich_rule=f"index=wineventlog {converted_rule[0]} {add_query}" #aggiungo la parte di query che assegna lo score + invio all'indice di Splunk "risk"
        #perchè "converted_rule[0]"? perchè la funzione backend.convert_rule potrebbe restituire più query da un'unica regola SIGMA, quindi ne teniamo 1.
        ##fix, aggiunto index=wineventlog perchè la regola sigma generata non ha index

        rich_rule_fixed=rich_rule.replace('source="WinEventLog:Microsoft-Windows-Sysmon/Operational"', 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
        #fix per la query convertita. processing pipeline di sysmon traduce male la source.
        #l'universal forwarder di splunk invia i dati con source XmlWinEventLog:Microsoft-Windows-Sysmon/Operational; ciò garantisce inoltre i campi parsati correttamente


        #invio i campi estratti regola per regola verso splunk tramite la funziona creata
        deploy_rule(rule_name, rich_rule_fixed, rule_description)

    except SigmaConversionError: #gestione errori di conversione importata da sigma.exceptions
        print(f"Errore di conversione della regola {rule_name}")
        continue #continua a iterare e a convertire le altre regole, dopo aver notificato quale regola "non va bene"
        
    
