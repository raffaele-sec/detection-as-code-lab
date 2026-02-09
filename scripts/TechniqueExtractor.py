import sys
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCollectionError
import yaml

rules_path="./rules/"
techniques_fields = {
    "api_version" : 2,
    "techniques" : []
    }
#creo i campi base che dovrà avere il file "techniques.yaml" da passare a dettect.py


try:
    collected_rules=SigmaCollection.load_ruleset([rules_path])#carico le sigma rule dal repo
    for rule in collected_rules.rules:#itero le sigma rule presenti
        technique_id=str(rule.tags[0]).upper().replace("ATTACK.","")#trasforma in stringa e in maiuscolo il campo tag, che contiene la tecnica MITRE, eliminando la parte "ATTACK."
        rule_name=rule.title

        techniques_fields["techniques"].append({ #creo il file gestendolo come una lista di dizionari, rispettando il format di esempio del file "techniques.yaml" 
            "technique_id" : f"{technique_id}",
            "score" : 1,
            "detection" : [{
                "applicable_to" : ['windows-lab'],
                "comment" : f"{rule_name}",
                }]
        })
    
    try:
        with open ('techniques.yaml', 'w') as file:
            yaml.safe_dump(techniques_fields, file) #creo il file YAML contenente tutte le technique ID MITRE ATT&CK coperte dalle Sigma rule nel repo
    except:
        print("Errore nella creazione del file 'techniques.yaml'")
        sys.exit(1)

except SigmaCollectionError:
    print("Errore nel caricamento delle Sigma Rule")
    sys.exit(1)