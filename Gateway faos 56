#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgroSafe-IoT : passerelle Raspberry Pi 3, phase 1
==================================================
Moteur de décision FAO-56 et contrôle de sécurité, aligné sur l'article 2 V2
(« Formal Verification of IoT Architectures ... Using CADP/LNT », version
corrigée) et sur le CDC corrigé (table R1-R11 où R4 et R9 deviennent des
règles de cohérence bilan/décision, couvertes par P13 et P14).

Ce fichier est la traduction opérationnelle du modèle LNT vérifié. Il produit,
à chaque cycle, les mêmes valeurs abstraites que les portes du modèle
(READ_SOL, READ_CUVE, ..., DECIDE, CHECK_SAFETY, LOG_EVENT) pour permettre la
comparaison trace par trace. Toute modification d'un seuil ou d'une règle
doit d'abord être reportée dans le modèle LNT.

Correspondance avec l'article 2 V2
----------------------------------
§3.3  États discrets      : NORMAL / ALARME / CRITIQUE, OK / HAUTE,
                            PLEINE / VIDE / FUITE.
§3.4  H1                  : délai d'absence de trame (P6) et cache de Dr.
§3.4  H2, §5.3            : dérive > 15 % par cycle de 10 min (P7) et marge
                            d'incertitude de 5 % dans la décision.
§3.4  H5                  : p constant par culture ; Kc du maïs par stade.
§3.5  4 équations FAO-56  : TAW, RAW, ETc, Dr avec P et I, 0 <= Dr <= TAW.
§3.5  7 conditions de danger (SECURITE impose BLOQUE) :
        P1 cuve vide (R2)            P5 fuite réseau (R1, R11 fuite)
        P2 fuite de cuve (R1)        P6 perte LoRa (R8)
        P3 température haute (R3)    P7 dérive capteur (R1)
        P4 pluie (R6)
Tableau 4 : P13 (R4) et P14 (R9), cohérence verdict/décision.
            P15 : tout blocage est journalisé LOG_ALERTE.

Contrôles conservés hors du périmètre du modèle (ils ne peuvent que bloquer
davantage, jamais autoriser) : R7 cohérence vanne/pompe, R11 blocage de
canalisation. R5 est une alerte d'information, non bloquante.

Ordre d'un cycle :
    1. Réception de la trame d'un nœud (ou constat d'absence de trame)
    2. Bilan hydrique FAO-56                       (TAW_CALC, côté gateway)
    3. Verdict DR_OK / DR_DEPASSE et décision      (DECISION)
    4. Contrôle de sécurité, priorité absolue      (SECURITE)
    5. Commande de l'actionneur et journalisation  (ACTIONNEURS, JOURNAL)

Thèse : Formal Validation of IoT Architecture
"""

import csv
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 1. PARAMÈTRES FAO-56 (article 2 V2, §3.5)
# ---------------------------------------------------------------------------
# Allen et al. (1998), FAO-56 : p (Tab. 22), Kc (Tab. 12). θfc et θwp sont les
# valeurs du site de Rabat retenues dans l'article. À ajuster après
# calibration du capteur capacitif V1.2.

CULTURES = {
    "maraichage": {
        "p": 0.45,            # constant (H5)
        "Zr": 0.35,           # m, dans la plage 0,30 à 0,60 m de l'article
        "theta_fc": 0.32,
        "theta_wp": 0.13,
        "Kc": 0.95,           # constant : aucun calendrier de stades fixé pour le maraîchage
        "regle_pluie_active": True,    # P4/R6 active
    },
    "mais": {
        "p": 0.55,            # constant (H5)
        "Zr": 0.55,           # m, valeur de l'article
        "theta_fc": 0.32,
        "theta_wp": 0.13,
        "Kc": None,           # par stade, voir kc_mais()
        "regle_pluie_active": False,   # P4/R6 désactivée en saison maïs
    },
}

# Kc du maïs par stade (CDC §2.2, FAO-56 Tab. 12) : jours après semis.
KC_MAIS_INI, KC_MAIS_MID, KC_MAIS_END = 0.30, 1.20, 0.60
J_FIN_INI, J_FIN_DEV, J_FIN_MID, J_FIN_LATE = 25, 55, 105, 125

# Marge d'incertitude de la décision (article §5.3) : le capteur V1.2 est
# précis à ±5 % de teneur en eau après calibration. Les frontières
# NORMAL/ALARME et ALARME/CRITIQUE sont avancées de 5 % pour irriguer avant
# que la limite réelle soit atteinte. 0.0 rend la comparaison stricte.
MARGE_INCERTITUDE = 0.05

# ---------------------------------------------------------------------------
# 2. SEUILS DE SÉCURITÉ
# ---------------------------------------------------------------------------
SEUIL_CUVE_VIDE_PCT = 20.0          # P1/R2 : VIDE si niveau <= 20 %
SEUIL_BAISSE_CUVE_PCT = 2.0         # P2/R1 : FUITE si baisse > 2 points en 1 cycle, vanne fermée (à calibrer)
SEUIL_TEMP_MAX_C = 40.0             # P3/R3 : HAUTE si >= 40 °C
SEUIL_PRESSION_MIN_BAR = 0.5        # P5/R1 : FUITE_RESEAU hors de [0,5 ; 3,0] bar
SEUIL_PRESSION_MAX_BAR = 3.0
SEUIL_DEBIT_FUITE_L_MIN = 0.5       # P5/R11 : débit > 0,5 L/min vanne fermée
SEUIL_LORA_RSSI_MIN = -120          # P6/R8 : dBm
SEUIL_LORA_SNR_MIN = -20            # P6/R8 : dB
DUREE_SUPERCADRE_S = 600            # TDMA, article §3.1
TIMEOUT_TRAME_S = 2 * DUREE_SUPERCADRE_S   # P6/R8 : 2 supercadres sans trame (configurable, H1)
SEUIL_DERIVE_CAPTEUR_PCT = 15.0     # P7/R1 : |Δθ| > 15 points par cycle de 10 min (H2)
DUREE_CYCLE_S = 600                 # cycle nominal de 10 min
ECART_MAX_CYCLES_CONSECUTIFS_S = 2 * DUREE_CYCLE_S  # au-delà, P7 et P2 ne comparent plus

SEUIL_TEMP_ALERTE_CHALEUR_C = 32.0  # R5 : alerte d'information
DELAI_MAX_SANS_IRRIGATION_CHALEUR_H = 48

# ---------------------------------------------------------------------------
# 3. STRUCTURES DE DONNÉES
# ---------------------------------------------------------------------------
@dataclass
class LectureNoeud:
    """Contenu d'une trame LoRa reçue d'un nœud."""
    noeud_id: int
    culture: str                 # "maraichage" ou "mais"
    humidite_sol_pct: float      # capteur capacitif V1.2, après calibration
    temp_air_c: float            # DHT22
    pression_bar: float          # pression réseau
    niveau_cuve_pct: float       # JSN-SR04T
    debit_l_min: float           # YF-S201
    vanne_ouverte: bool          # état rapporté
    pompe_active: bool
    pluie_detectee: bool         # VL-83
    lora_rssi: float
    lora_snr: float
    horodatage: str              # ISO 8601, horloge NTP de la gateway


@dataclass
class EtatNoeud:
    """Cache conservé par la gateway pour chaque nœud (H1)."""
    culture: str
    dr_mm: float = 0.0                                  # Dr du dernier cycle
    humidite_precedente_pct: Optional[float] = None
    niveau_cuve_precedent_pct: Optional[float] = None
    derniere_trame: Optional[datetime.datetime] = None
    derniere_irrigation: Optional[datetime.datetime] = None


# ---------------------------------------------------------------------------
# 4. TAW_CALC : BILAN HYDRIQUE FAO-56 (article §3.5)
# ---------------------------------------------------------------------------
def kc_mais(jours_apres_semis: Optional[float]) -> float:
    """Kc du maïs par stade (CDC §2.2). Sans date de semis : mi-saison (1,20)."""
    if jours_apres_semis is None:
        return KC_MAIS_MID
    j = jours_apres_semis
    if j <= J_FIN_INI:
        return KC_MAIS_INI
    if j <= J_FIN_DEV:
        return KC_MAIS_INI + (KC_MAIS_MID - KC_MAIS_INI) * (j - J_FIN_INI) / (J_FIN_DEV - J_FIN_INI)
    if j <= J_FIN_MID:
        return KC_MAIS_MID
    if j <= J_FIN_LATE:
        return KC_MAIS_MID + (KC_MAIS_END - KC_MAIS_MID) * (j - J_FIN_MID) / (J_FIN_LATE - J_FIN_MID)
    return KC_MAIS_END


def coefficient_cultural(culture: str, jours_apres_semis: Optional[float] = None) -> float:
    if culture == "mais":
        return kc_mais(jours_apres_semis)
    return CULTURES[culture]["Kc"]


def calcul_bilan_hydrique(culture: str, et0_mm_jour: float, dr_precedent_mm: float,
                          pluie_mm: float = 0.0, irrigation_mm: float = 0.0,
                          jours_apres_semis: Optional[float] = None,
                          fraction_jour: float = 1.0) -> dict:
    """
    TAW = 1000 (θfc - θwp) Zr
    RAW = p TAW
    ETc = Kc ET0
    Dr(t) = Dr(t-1) - P - I + ETc + DP,  borné à 0 <= Dr <= TAW (FAO-56, éq. 86)

    pluie_mm      : précipitation effective P depuis le cycle précédent
    irrigation_mm : irrigation I appliquée au cycle précédent
    fraction_jour : part de journée couverte par le cycle (1.0 en pas journalier,
                    1/144 pour un cycle de 10 min) ; ETc est en mm/jour.
    L'excédent qui ramènerait Dr sous 0 correspond à la percolation DP.
    """
    params = CULTURES[culture]
    kc = coefficient_cultural(culture, jours_apres_semis)

    taw = 1000.0 * (params["theta_fc"] - params["theta_wp"]) * params["Zr"]
    raw = params["p"] * taw
    etc = kc * et0_mm_jour
    dr_brut = dr_precedent_mm - pluie_mm - irrigation_mm + etc * fraction_jour
    dr = min(max(0.0, dr_brut), taw)
    dp = max(0.0, -dr_brut)

    # Valeurs non arrondies : Dr est réinjecté au cycle suivant.
    return {"Kc": kc, "TAW": taw, "RAW": raw, "ETc": etc, "Dr": dr, "DP": dp}


# ---------------------------------------------------------------------------
# 5. DECISION : VERDICT ET PROPOSITION (article §3.3 et §3.5)
# ---------------------------------------------------------------------------
def etat_sol(bilan: dict, marge: float = MARGE_INCERTITUDE) -> str:
    """READ_SOL : NORMAL, ALARME ou CRITIQUE, frontières avancées de la marge."""
    dr = bilan["Dr"]
    if dr >= (1.0 - marge) * bilan["TAW"]:
        return "CRITIQUE"
    if dr >= (1.0 - marge) * bilan["RAW"]:
        return "ALARME"
    return "NORMAL"


def verdict_bilan(bilan: dict, marge: float = MARGE_INCERTITUDE) -> str:
    """RECV_BILAN / EMIT_DECISION : DR_DEPASSE si le sol n'est plus NORMAL."""
    return "DR_OK" if etat_sol(bilan, marge) == "NORMAL" else "DR_DEPASSE"


def decision_agronomique(verdict: str) -> str:
    """DECIDE : IRRIGUER si DR_DEPASSE, ATTENDRE sinon (article §3.5)."""
    return "IRRIGUER" if verdict == "DR_DEPASSE" else "ATTENDRE"


def controle_coherence(verdict: str, decision: str) -> list:
    """R4 (P13) et R9 (P14) : la décision doit suivre le verdict du bilan."""
    if verdict == "DR_DEPASSE" and decision != "IRRIGUER":
        return ["R4/P13: incohérence, DR_DEPASSE sans proposition IRRIGUER"]
    if verdict == "DR_OK" and decision != "ATTENDRE":
        return ["R9/P14: incohérence, DR_OK sans proposition ATTENDRE"]
    return []


# ---------------------------------------------------------------------------
# 6. SECURITE : 7 CONDITIONS DE DANGER (priorité absolue)
# ---------------------------------------------------------------------------
def _consecutif(t1: Optional[datetime.datetime], t2: datetime.datetime) -> bool:
    return t1 is not None and 0 < (t2 - t1).total_seconds() <= ECART_MAX_CYCLES_CONSECUTIFS_S


def etats_capteurs(lecture: LectureNoeud, humidite_precedente_pct: Optional[float],
                   niveau_cuve_precedent_pct: Optional[float],
                   lora_perdu: bool = False) -> dict:
    """Valeurs abstraites des 6 portes READ_* de sécurité (hors READ_SOL)."""
    params = CULTURES[lecture.culture]

    if lecture.niveau_cuve_pct <= SEUIL_CUVE_VIDE_PCT:
        cuve = "VIDE"
    elif (niveau_cuve_precedent_pct is not None and not lecture.vanne_ouverte
          and not lecture.pompe_active
          and niveau_cuve_precedent_pct - lecture.niveau_cuve_pct > SEUIL_BAISSE_CUVE_PCT):
        cuve = "FUITE"
    else:
        cuve = "PLEINE"

    temp = "HAUTE" if lecture.temp_air_c >= SEUIL_TEMP_MAX_C else "OK"

    fuite_reseau = (lecture.pression_bar < SEUIL_PRESSION_MIN_BAR
                    or lecture.pression_bar > SEUIL_PRESSION_MAX_BAR
                    or (not lecture.vanne_ouverte and lecture.debit_l_min > SEUIL_DEBIT_FUITE_L_MIN))
    pression = "FUITE_RESEAU" if fuite_reseau else "NORMALE"

    lora_degradee = (lecture.lora_rssi < SEUIL_LORA_RSSI_MIN
                     or lecture.lora_snr < SEUIL_LORA_SNR_MIN)
    lora = "PERDU" if (lora_perdu or lora_degradee) else "OK"

    derive = (humidite_precedente_pct is not None
              and abs(lecture.humidite_sol_pct - humidite_precedente_pct) > SEUIL_DERIVE_CAPTEUR_PCT)
    delta = "DERIVE" if derive else "STABLE"

    pluie = "PLUIE" if (params["regle_pluie_active"] and lecture.pluie_detectee) else "SEC"

    return {"READ_CUVE": cuve, "READ_TEMP": temp, "READ_PRESSION": pression,
            "READ_LORA": lora, "READ_DELTA": delta, "READ_PLUIE": pluie}


def verification_securite(decision_proposee: str, lecture: LectureNoeud, etats: dict,
                          derniere_irrigation: Optional[datetime.datetime] = None,
                          maintenant: Optional[datetime.datetime] = None) -> tuple:
    """
    Retourne (decision_finale, alertes_bloquantes_modele, alertes_hors_modele,
    alertes_info). Toute condition de danger impose BLOQUER, quelle que soit
    la proposition de DECISION. Seul point de sortie vers l'actionneur : une
    commande manuelle (R10) passe aussi par cette fonction.
    """
    if decision_proposee not in ("IRRIGUER", "ATTENDRE"):
        raise ValueError(f"Proposition inconnue : {decision_proposee}")

    modele, hors_modele, info = [], [], []

    # 7 conditions de danger du modèle (article §3.5)
    if etats["READ_CUVE"] == "VIDE":
        modele.append(f"P1/R2: cuve vide ({lecture.niveau_cuve_pct} %)")
    if etats["READ_CUVE"] == "FUITE":
        modele.append("P2/R1: fuite de cuve (baisse de niveau, vanne fermée)")
    if etats["READ_TEMP"] == "HAUTE":
        modele.append(f"P3/R3: température haute ({lecture.temp_air_c} °C)")
    if etats["READ_PLUIE"] == "PLUIE":
        modele.append("P4/R6: pluie détectée")
    if etats["READ_PRESSION"] == "FUITE_RESEAU":
        if not (SEUIL_PRESSION_MIN_BAR <= lecture.pression_bar <= SEUIL_PRESSION_MAX_BAR):
            modele.append(f"P5/R1: pression réseau anormale ({lecture.pression_bar} bar)")
        if not lecture.vanne_ouverte and lecture.debit_l_min > SEUIL_DEBIT_FUITE_L_MIN:
            modele.append(f"P5/R11: fuite active, débit {lecture.debit_l_min} L/min vanne fermée")
    if etats["READ_LORA"] == "PERDU":
        modele.append("P6/R8: liaison LoRa perdue ou dégradée")
    if etats["READ_DELTA"] == "DERIVE":
        modele.append("P7/R1: dérive du capteur d'humidité > 15 % en un cycle")

    # Contrôles matériels hors modèle (conservateurs)
    if lecture.vanne_ouverte != lecture.pompe_active:
        hors_modele.append("HM/R7: incohérence vanne/pompe")
    if lecture.vanne_ouverte and lecture.debit_l_min == 0:
        hors_modele.append("HM/R11: blocage de canalisation (vanne ouverte, débit nul)")

    # R5 : alerte d'information, non bloquante
    if derniere_irrigation is not None and maintenant is not None:
        heures = (maintenant - derniere_irrigation).total_seconds() / 3600
        if lecture.temp_air_c >= SEUIL_TEMP_ALERTE_CHALEUR_C and heures > DELAI_MAX_SANS_IRRIGATION_CHALEUR_H:
            info.append(f"R5: {heures:.1f} h sans irrigation en période de forte chaleur")

    if modele or hors_modele:
        return "BLOQUER", modele, hors_modele, info
    return decision_proposee, modele, hors_modele, info


# ---------------------------------------------------------------------------
# 7. PASSERELLE : CACHE, CYCLE, ABSENCE DE TRAME, MODE MANUEL, JOURNAL
# ---------------------------------------------------------------------------
ENTETE_JOURNAL = [
    "horodatage", "noeud_id", "culture", "source",
    "et0_mm", "pluie_mm", "irrigation_mm", "Kc", "TAW", "RAW", "ETc", "Dr", "DP",
    "READ_SOL", "READ_CUVE", "READ_TEMP", "READ_PRESSION", "READ_LORA", "READ_DELTA", "READ_PLUIE",
    "RECV_BILAN", "DECIDE", "CHECK_SAFETY", "LOG_EVENT", "decision_finale", "dose_mm",
    "alertes_modele", "alertes_hors_modele", "alertes_info",
    "humidite_sol_pct", "humidite_precedente_pct", "temp_air_c", "pression_bar",
    "niveau_cuve_pct", "niveau_cuve_precedent_pct", "debit_l_min",
    "vanne_ouverte", "pompe_active", "pluie_detectee", "lora_rssi", "lora_snr",
]


class Passerelle:
    def __init__(self, log_path="agrosafe_journal.csv", marge=MARGE_INCERTITUDE):
        self.log_path = Path(log_path)
        self.marge = marge
        self.noeuds = {}            # noeud_id -> EtatNoeud
        self.derniere_lecture = {}  # noeud_id -> dernière LectureNoeud reçue

    def etat(self, noeud_id: int, culture: str) -> EtatNoeud:
        if noeud_id not in self.noeuds:
            self.noeuds[noeud_id] = EtatNoeud(culture=culture)
        return self.noeuds[noeud_id]

    # --- cycle normal : une trame reçue -----------------------------------
    def traiter_trame(self, lecture: LectureNoeud, et0_mm_jour: float,
                      pluie_mm: float = 0.0, irrigation_mm: float = 0.0,
                      jours_apres_semis: Optional[float] = None,
                      fraction_jour: float = 1.0,
                      humidite_precedente_pct: Optional[float] = None,
                      niveau_cuve_precedent_pct: Optional[float] = None) -> dict:
        """
        humidite_precedente_pct et niveau_cuve_precedent_pct : si None, la
        gateway prend la valeur du cache, mais seulement si la trame
        précédente date de moins de 2 cycles (P7 et P2 sont définis par cycle
        de 10 min). Le simulateur peut les fournir pour injecter une faute.
        """
        maintenant = datetime.datetime.fromisoformat(lecture.horodatage)
        e = self.etat(lecture.noeud_id, lecture.culture)
        consecutif = _consecutif(e.derniere_trame, maintenant)
        if humidite_precedente_pct is None and consecutif:
            humidite_precedente_pct = e.humidite_precedente_pct
        if niveau_cuve_precedent_pct is None and consecutif:
            niveau_cuve_precedent_pct = e.niveau_cuve_precedent_pct

        resultat = self._cycle(lecture, e, maintenant, et0_mm_jour, pluie_mm, irrigation_mm,
                               jours_apres_semis, fraction_jour, humidite_precedente_pct,
                               niveau_cuve_precedent_pct, lora_perdu=False, source="AUTO")

        e.humidite_precedente_pct = lecture.humidite_sol_pct
        e.niveau_cuve_precedent_pct = lecture.niveau_cuve_pct
        e.derniere_trame = maintenant
        return resultat

    # --- H1 : absence de trame --------------------------------------------
    def noeuds_sans_trame(self, maintenant: datetime.datetime) -> list:
        """Nœuds dont la dernière trame date de plus de TIMEOUT_TRAME_S."""
        return [nid for nid, e in self.noeuds.items()
                if e.derniere_trame is not None
                and (maintenant - e.derniere_trame).total_seconds() > TIMEOUT_TRAME_S]

    def traiter_absence_trame(self, noeud_id: int, maintenant: datetime.datetime,
                              et0_mm_jour: float, pluie_mm: float = 0.0,
                              irrigation_mm: float = 0.0,
                              jours_apres_semis: Optional[float] = None,
                              fraction_jour: float = 1.0) -> dict:
        """
        P6 : sans trame, READ_LORA = PERDU et SECURITE bloque. Le bilan
        continue sur le Dr en cache (H1), avec l'ET0 et la pluie connues de la
        gateway. Les capteurs du nœud sont repris de la dernière trame.
        """
        e = self.noeuds[noeud_id]
        derniere = self.derniere_lecture.get(noeud_id)
        if derniere is None:
            raise KeyError(f"Aucune trame antérieure pour le nœud {noeud_id}")
        lecture = LectureNoeud(**{**derniere.__dict__, "horodatage": maintenant.isoformat()})
        return self._cycle(lecture, e, maintenant, et0_mm_jour, pluie_mm, irrigation_mm,
                           jours_apres_semis, fraction_jour, None, None,
                           lora_perdu=True, source="ABSENCE_TRAME")

    # --- R10 : commande manuelle ------------------------------------------
    def commande_manuelle(self, lecture: LectureNoeud) -> dict:
        """
        R10 : une demande d'irrigation de l'opérateur passe par SECURITE comme
        une proposition IRRIGUER. Le bilan n'est pas modifié. Aucune autre
        voie ne commande la vanne.
        """
        maintenant = datetime.datetime.fromisoformat(lecture.horodatage)
        e = self.etat(lecture.noeud_id, lecture.culture)
        etats = etats_capteurs(lecture, None, None)
        finale, modele, hors, info = verification_securite(
            "IRRIGUER", lecture, etats, e.derniere_irrigation, maintenant)
        if finale == "IRRIGUER":
            e.derniere_irrigation = maintenant
        return {"decision_finale": finale, "CHECK_SAFETY": "AUTORISE" if finale == "IRRIGUER" else "BLOQUE",
                "alertes": modele + hors + info, "source": "MANUEL"}

    # --- cœur du cycle ------------------------------------------------------
    def _cycle(self, lecture, e, maintenant, et0, pluie_mm, irrigation_mm, jours_apres_semis,
               fraction_jour, humidite_prec, niveau_prec, lora_perdu, source) -> dict:
        bilan = calcul_bilan_hydrique(lecture.culture, et0, e.dr_mm, pluie_mm, irrigation_mm,
                                      jours_apres_semis, fraction_jour)
        sol = etat_sol(bilan, self.marge)
        verdict = verdict_bilan(bilan, self.marge)
        proposee = decision_agronomique(verdict)

        etats = etats_capteurs(lecture, humidite_prec, niveau_prec, lora_perdu)
        finale, modele, hors, info = verification_securite(
            proposee, lecture, etats, e.derniere_irrigation, maintenant)

        incoherences = controle_coherence(verdict, proposee)
        if incoherences:          # défaut logiciel : repli sûr
            finale, hors = "BLOQUER", hors + incoherences

        check_safety = "AUTORISE" if finale == "IRRIGUER" else "BLOQUE"
        log_event = "LOG_ALERTE" if (modele or hors) else "LOG_OK"   # P15
        dose_mm = bilan["Dr"] if finale == "IRRIGUER" else 0.0       # retour à la capacité au champ

        e.dr_mm = bilan["Dr"]
        if finale == "IRRIGUER":
            e.derniere_irrigation = maintenant
        if source == "AUTO":
            self.derniere_lecture[lecture.noeud_id] = lecture

        resultat = {
            "bilan": bilan, "READ_SOL": sol, **etats,
            "RECV_BILAN": verdict, "DECIDE": proposee, "CHECK_SAFETY": check_safety,
            "LOG_EVENT": log_event, "decision_finale": finale, "dose_mm": dose_mm,
            "alertes_modele": modele, "alertes_hors_modele": hors, "alertes_info": info,
            "source": source,
        }
        self.journaliser(lecture, resultat, et0, pluie_mm, irrigation_mm, humidite_prec, niveau_prec)
        return resultat

    def journaliser(self, lecture, r, et0, pluie_mm, irrigation_mm, humidite_prec, niveau_prec):
        b = r["bilan"]
        existe = self.log_path.exists()
        with open(self.log_path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if not existe:
                w.writerow(ENTETE_JOURNAL)
            w.writerow([
                lecture.horodatage, lecture.noeud_id, lecture.culture, r["source"],
                et0, pluie_mm, irrigation_mm, round(b["Kc"], 3), round(b["TAW"], 2),
                round(b["RAW"], 2), round(b["ETc"], 3), round(b["Dr"], 3), round(b["DP"], 3),
                r["READ_SOL"], r["READ_CUVE"], r["READ_TEMP"], r["READ_PRESSION"],
                r["READ_LORA"], r["READ_DELTA"], r["READ_PLUIE"],
                r["RECV_BILAN"], r["DECIDE"], r["CHECK_SAFETY"], r["LOG_EVENT"],
                r["decision_finale"], round(r["dose_mm"], 3),
                ";".join(r["alertes_modele"]), ";".join(r["alertes_hors_modele"]),
                ";".join(r["alertes_info"]),
                lecture.humidite_sol_pct, humidite_prec, lecture.temp_air_c, lecture.pression_bar,
                lecture.niveau_cuve_pct, niveau_prec, lecture.debit_l_min,
                lecture.vanne_ouverte, lecture.pompe_active, lecture.pluie_detectee,
                lecture.lora_rssi, lecture.lora_snr,
            ])


# ---------------------------------------------------------------------------
# EXEMPLE : à remplacer par la boucle de réception LoRa réelle
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    gw = Passerelle()
    t0 = datetime.datetime(2026, 12, 1, 8, 0)
    lecture = LectureNoeud(
        noeud_id=1, culture="maraichage", humidite_sol_pct=28.0, temp_air_c=22.5,
        pression_bar=1.5, niveau_cuve_pct=65.0, debit_l_min=0.0,
        vanne_ouverte=False, pompe_active=False, pluie_detectee=False,
        lora_rssi=-90, lora_snr=-5, horodatage=t0.isoformat(),
    )
    r = gw.traiter_trame(lecture, et0_mm_jour=2.5)
    print(r["READ_SOL"], r["RECV_BILAN"], r["DECIDE"], r["CHECK_SAFETY"], r["LOG_EVENT"])
