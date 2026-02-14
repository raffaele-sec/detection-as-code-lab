

### ATTUALMENTE LO SCRIPT E' UNA BOZZA! INDICA SOLO CIÒ CHE DOVREBBE FARE! ###


import sys
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCollectionError
import json

rules_path="./rules/"
json_fields = { #definisco staticamente i campi del layer JSON da passare al MITRE ATT&CK Navigator
    "name" : "Windows Lab - Sigma Coverage (v18)",
    "versions" : {
        "attack": "18",
        "navigator": "5.0",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Copertura rilevamenti generata automaticamente",
    "filters": {
        "platforms": [
            "Windows"
        ]
    },
        "sorting": 3,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False
    },
     "hideDisabled": False,
    "gradient": {
        "colors": [
            "#ffffff",
            "#66ff66"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "techniques": []
    }

    
    
    


try:
    collected_rules=SigmaCollection.load_ruleset([rules_path])#carico le sigma rule dal repo
    for rule in collected_rules.rules:#itero le sigma rule presenti

        technique_id=str(rule.tags[0]).upper().replace("ATTACK.","")#trasforma in stringa e in maiuscolo il campo tag, che contiene la tecnica MITRE, eliminando la parte "ATTACK."
        rule_name=rule.title #prendo il nome della regola Sigma da inserire nei commenti del layer


        tech_presente = False
        for techn in json_fields["techniques"]: #aggiunto controllo per vedere se la Technique ID è già presente, in maniera tale da non sovrascrivere nulla sul layer
            if techn["techniqueID"] == technique_id: # SE la "technique_id" estratta dalle rule nel ciclo attuale corrisponde a una "techniqueID" presente nella lista ""techniques": []"
                techn["comment"]+=f"\n{rule_name}" #aggiunge il commento con il nome della regola, così da avere una technique ID con più rule name nei commenti
                tech_presente = True
                break


        if tech_presente == False:
            json_fields["techniques"].append( #inserisco nel dizionario i campi estratti dalle Sigma rule, per poter creare poi il JSON layer di copertura delle ruel
                {
                "techniqueID": f"{technique_id}",
                "score": 1,
                "color": "#66ff66",
                "comment": f"{rule_name}",
                "enabled": True
                }

            )

    

    with open ("mitre_navigator_layer.json", "w") as file:
        JSONlayer= json.dump(json_fields, file, indent=4)

except SigmaCollectionError:
    print("Errore nel caricamento delle Sigma Rule")
    sys.exit(1)