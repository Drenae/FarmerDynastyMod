# Farmer Dynasty Mod Loader

Première version du chargeur de mods externe pour Farmer's Dynasty.

## Principe

Le loader garde `FarmersDynasty.exe` intact. Il lance le jeu suspendu, vérifie sa version, applique les patches des mods activés directement en mémoire, puis reprend l'exécution.

L'utilisateur n'a aucune adresse mémoire ni octet machine à renseigner.

## Structure

```
ModLoader/
  farmer_dynasty_mod_loader.py
  config.json
  Mods/
    FreeWorkers/
      mod.json
```

## V1

- Windows uniquement.
- Détection du chemin du jeu via `config.json` ou chemins courants.
- Vérification SHA-256 de l'EXE.
- Vérification des octets originaux avant chaque patch.
- Application en mémoire avec `WriteProcessMemory`.
- Aucun changement permanent de `FarmersDynasty.exe`.
- Premier mod : **Free Workers**, basé sur le patch déjà validé en jeu.
- Un mod incompatible arrête le lancement avant modification hasardeuse.

## Lancement développement

Python 3.10+ :

```powershell
cd "D:\Games\Farmers Dynasty\data\ModLoader"
python .\farmer_dynasty_mod_loader.py
```

Le chemin peut être renseigné dans `config.json`.

> Faster Crop Growth n'est volontairement pas inclus tant que la formule de croissance réelle n'a pas été identifiée dans le code du jeu.
