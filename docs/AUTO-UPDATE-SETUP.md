# Auto-Update Einrichtung – einmalig zuhause

Nach diesem einmaligen Setup läuft alles automatisch: Claude pusht Code,
erstellt einen PR, du mergst, und der FinestraMiner aktualisiert sich selbst.

## Was passiert automatisch nach deinem Merge

1. GitHub Actions erkennt den Merge auf `main`
2. Der Workflow liest die Version aus `config.yaml`
3. Ein neues GitHub Release wird automatisch erstellt
4. Der FinestraMiner erkennt das neue Release und aktualisiert das Add-on

## Einmalige Schritte auf dem FinestraMiner

### 1. Automatische Updates für das Add-on aktivieren

1. Home Assistant öffnen → **Einstellungen** → **Add-ons**
2. **H.A.D.E.S. Build Worker** öffnen
3. Oben rechts auf die **drei Punkte (⋮)** klicken
4. **„Automatische Updates"** aktivieren (Schieberegler auf Ein)

Das ist alles. Ab sofort zieht HA bei jedem neuen Release automatisch die
neue Version und startet das Add-on neu.

### 2. Repository auf neuste Version refreshen (falls nötig)

Falls das Add-on noch nicht auf dem neusten Stand ist:

1. **Einstellungen** → **Add-ons** → **Add-on Store**
2. Oben rechts auf die **drei Punkte (⋮)** klicken → **Repositories**
3. Repository `https://github.com/engelssebastian239-ops/hades-build-worker-addon`
   ist bereits eingetragen – kurz entfernen und wieder hinzufügen um zu refreshen

## Workflow danach (kein manuelles Eingreifen mehr nötig)

```
Du sagst Claude was geändert werden soll
→ Claude schreibt den Code, erhöht die Versionsnummer
→ Claude erstellt einen PR auf GitHub
→ Du merkst den PR (ein Klick in GitHub)
→ GitHub Actions baut automatisch ein Release
→ FinestraMiner erkennt das Release und updated sich selbst
```

## Hinweis zur Versionsnummer

Damit ein neues Release erkannt wird, muss die Version in
`hades_build_worker/config.yaml` und `package.json` erhöht sein.
Claude macht das automatisch bei jeder Änderung.
