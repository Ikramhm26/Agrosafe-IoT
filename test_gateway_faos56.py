# -*- coding: utf-8 -*-
"""Tests de conformité de gateway_faos56.py à l'article 2 V2 (pytest)."""
import datetime as dt
import pytest
import gateway_faos56 as g

T0 = dt.datetime(2026, 12, 1, 8, 0)


def lec(t=T0, **k):
    base = dict(noeud_id=1, culture="maraichage", humidite_sol_pct=28.0, temp_air_c=22.0,
                pression_bar=1.5, niveau_cuve_pct=65.0, debit_l_min=0.0, vanne_ouverte=False,
                pompe_active=False, pluie_detectee=False, lora_rssi=-90, lora_snr=-5,
                horodatage=t.isoformat())
    base.update(k)
    return g.LectureNoeud(**base)


@pytest.fixture
def gw(tmp_path):
    return g.Passerelle(log_path=tmp_path / "j.csv")


# --- §3.5 : équations FAO-56 -------------------------------------------------
def test_taw_raw_maraichage():
    b = g.calcul_bilan_hydrique("maraichage", 2.5, 0.0)
    assert b["TAW"] == pytest.approx(66.5)
    assert b["RAW"] == pytest.approx(29.925)


def test_taw_mais_dans_plage_article():
    assert 100 <= g.calcul_bilan_hydrique("mais", 0, 0)["TAW"] <= 140


def test_pluie_et_irrigation_reduisent_dr():
    b = g.calcul_bilan_hydrique("maraichage", 4.0, 30.0, pluie_mm=10, irrigation_mm=5)
    assert b["Dr"] == pytest.approx(30 - 10 - 5 + 0.95 * 4)


def test_dr_borne_a_taw_et_a_zero():
    assert g.calcul_bilan_hydrique("maraichage", 10, 66.0)["Dr"] == pytest.approx(66.5)
    b = g.calcul_bilan_hydrique("maraichage", 2, 5, pluie_mm=20)
    assert b["Dr"] == 0 and b["DP"] == pytest.approx(20 - 5 - 1.9)


def test_fraction_jour():
    b = g.calcul_bilan_hydrique("maraichage", 1.44, 0, fraction_jour=1 / 144)
    assert b["Dr"] == pytest.approx(0.95 * 0.01)


@pytest.mark.parametrize("j,kc", [(0, 0.30), (25, 0.30), (40, 0.75), (80, 1.20), (115, 0.90), (200, 0.60), (None, 1.20)])
def test_kc_mais_par_stade(j, kc):
    assert g.kc_mais(j) == pytest.approx(kc)


# --- §3.3 et §5.3 : états du sol avec marge de 5 % --------------------------
@pytest.mark.parametrize("dr,attendu", [(28.0, "NORMAL"), (28.5, "ALARME"), (60, "ALARME"), (63.2, "CRITIQUE"), (66.5, "CRITIQUE")])
def test_etat_sol_marge(dr, attendu):
    b = {"Dr": dr, "RAW": 29.925, "TAW": 66.5}
    assert g.etat_sol(b) == attendu


def test_marge_nulle_stricte():
    b = {"Dr": 29.0, "RAW": 29.925, "TAW": 66.5}
    assert g.etat_sol(b, marge=0.0) == "NORMAL"


def test_decision_suit_verdict():
    assert g.decision_agronomique("DR_DEPASSE") == "IRRIGUER"
    assert g.decision_agronomique("DR_OK") == "ATTENDRE"
    assert g.controle_coherence("DR_DEPASSE", "IRRIGUER") == []
    assert g.controle_coherence("DR_OK", "IRRIGUER")[0].startswith("R9/P14")
    assert g.controle_coherence("DR_DEPASSE", "ATTENDRE")[0].startswith("R4/P13")


# --- §3.5 : 7 conditions de danger --------------------------------------------
CAS_DANGER = [
    ("P1/R2", dict(niveau_cuve_pct=20.0)),
    ("P3/R3", dict(temp_air_c=40.0)),
    ("P4/R6", dict(pluie_detectee=True)),
    ("P5/R1", dict(pression_bar=0.4)),
    ("P5/R1", dict(pression_bar=3.1)),
    ("P5/R11", dict(debit_l_min=0.6)),
    ("P6/R8", dict(lora_rssi=-121)),
    ("P6/R8", dict(lora_snr=-21)),
]


@pytest.mark.parametrize("prefixe,k", CAS_DANGER)
def test_danger_bloque_irrigation(gw, prefixe, k):
    gw.noeuds[1] = g.EtatNoeud(culture="maraichage", dr_mm=40)  # DR_DEPASSE
    r = gw.traiter_trame(lec(**k), et0_mm_jour=2)
    assert r["DECIDE"] == "IRRIGUER"
    assert r["CHECK_SAFETY"] == "BLOQUE" and r["LOG_EVENT"] == "LOG_ALERTE"
    assert any(a.startswith(prefixe) for a in r["alertes_modele"])


def test_pluie_ignoree_en_mais(gw):
    gw.noeuds[1] = g.EtatNoeud(culture="mais", dr_mm=80)
    r = gw.traiter_trame(lec(culture="mais", pluie_detectee=True), et0_mm_jour=2)
    assert r["READ_PLUIE"] == "SEC" and r["CHECK_SAFETY"] == "AUTORISE"


def test_p7_derive_cycles_consecutifs(gw):
    gw.traiter_trame(lec(humidite_sol_pct=28), et0_mm_jour=0)
    r = gw.traiter_trame(lec(T0 + dt.timedelta(minutes=10), humidite_sol_pct=45), et0_mm_jour=0)
    assert r["READ_DELTA"] == "DERIVE" and any(a.startswith("P7/R1") for a in r["alertes_modele"])


def test_p7_pas_de_derive_au_pas_journalier(gw):
    gw.traiter_trame(lec(humidite_sol_pct=28), et0_mm_jour=0)
    r = gw.traiter_trame(lec(T0 + dt.timedelta(days=1), humidite_sol_pct=45), et0_mm_jour=0)
    assert r["READ_DELTA"] == "STABLE"


def test_p7_injection_par_simulateur(gw):
    r = gw.traiter_trame(lec(humidite_sol_pct=45), et0_mm_jour=0, humidite_precedente_pct=28)
    assert r["READ_DELTA"] == "DERIVE"


def test_p2_fuite_de_cuve(gw):
    gw.traiter_trame(lec(niveau_cuve_pct=65), et0_mm_jour=0)
    r = gw.traiter_trame(lec(T0 + dt.timedelta(minutes=10), niveau_cuve_pct=60), et0_mm_jour=0)
    assert r["READ_CUVE"] == "FUITE" and any(a.startswith("P2/R1") for a in r["alertes_modele"])


def test_p2_pas_de_fuite_si_pompe_active(gw):
    r = gw.traiter_trame(lec(niveau_cuve_pct=60, vanne_ouverte=True, pompe_active=True, debit_l_min=5),
                         et0_mm_jour=0, niveau_cuve_precedent_pct=65)
    assert r["READ_CUVE"] == "PLEINE"


# --- H1 : absence de trame et cache de Dr --------------------------------------
def test_absence_trame_bloque_et_garde_dr(gw):
    gw.traiter_trame(lec(), et0_mm_jour=5)
    dr = gw.noeuds[1].dr_mm
    t = T0 + dt.timedelta(seconds=g.TIMEOUT_TRAME_S + 1)
    assert gw.noeuds_sans_trame(t) == [1]
    r = gw.traiter_absence_trame(1, t, et0_mm_jour=5)
    assert r["READ_LORA"] == "PERDU" and r["CHECK_SAFETY"] == "BLOQUE"
    assert r["bilan"]["Dr"] == pytest.approx(dr + 0.95 * 5)


# --- hors modèle, R5, R10, P15 ---------------------------------------------------
def test_hors_modele_r7_r11(gw):
    r = gw.traiter_trame(lec(vanne_ouverte=True, pompe_active=False), et0_mm_jour=0)
    assert r["CHECK_SAFETY"] == "BLOQUE" and r["alertes_modele"] == []
    assert {a[:6] for a in r["alertes_hors_modele"]} == {"HM/R7:", "HM/R11"}


def test_r5_information_non_bloquante(gw):
    gw.noeuds[1] = g.EtatNoeud(culture="maraichage", dr_mm=40, derniere_irrigation=T0 - dt.timedelta(hours=72))
    r = gw.traiter_trame(lec(temp_air_c=35), et0_mm_jour=2)
    assert r["CHECK_SAFETY"] == "AUTORISE" and r["alertes_info"][0].startswith("R5")


def test_irrigation_autorisee_dose_et_retour_capacite(gw):
    gw.noeuds[1] = g.EtatNoeud(culture="maraichage", dr_mm=40)
    r = gw.traiter_trame(lec(), et0_mm_jour=2)
    assert r["CHECK_SAFETY"] == "AUTORISE" and r["LOG_EVENT"] == "LOG_OK"
    r2 = gw.traiter_trame(lec(T0 + dt.timedelta(days=1)), et0_mm_jour=2, irrigation_mm=r["dose_mm"])
    assert r2["bilan"]["Dr"] == pytest.approx(0.95 * 2)
    assert r2["RECV_BILAN"] == "DR_OK" and r2["DECIDE"] == "ATTENDRE"


def test_r10_commande_manuelle_soumise_a_securite(gw):
    assert gw.commande_manuelle(lec(niveau_cuve_pct=10))["decision_finale"] == "BLOQUER"
    assert gw.commande_manuelle(lec())["decision_finale"] == "IRRIGUER"


def test_journal_colonnes(gw):
    gw.traiter_trame(lec(), et0_mm_jour=2)
    entete = gw.log_path.read_text(encoding="utf-8").splitlines()[0].split(",")
    assert entete == g.ENTETE_JOURNAL
