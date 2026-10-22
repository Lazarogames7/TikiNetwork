"""Análisis reproducible del kit CIFOX. Solo stdlib. No conecta redes ni equipos OT."""
import csv
import hashlib
import json
from pathlib import Path
from math import isclose

ROOT = Path(__file__).resolve().parent

def aggregate(rows):
    it = sum(float(r['energy_it_kwh']) for r in rows)
    total = sum(float(r['energy_total_kwh']) for r in rows)
    water = sum(float(r['water_l']) for r in rows)
    return dict(rows=len(rows), energy_it_kwh=it, energy_total_kwh=total,
                water_l=water, pue=total/it if it else None,
                wue_captacion_l_kwh=water/it if it else None)

def main():
    source = ROOT / 'operaciones_simuladas.csv'
    rows = list(csv.DictReader(source.open(encoding='utf-8', newline='')))
    assert len(rows) == 504
    assert len({(r['site_id'],r['timestamp']) for r in rows}) == 504
    assert all(r['is_simulated'] == 'True' for r in rows)
    assert all(float(r['energy_total_kwh']) >= float(r['energy_it_kwh']) > 0 for r in rows)
    splits = {s: aggregate([r for r in rows if r['split']==s]) for s in ('referencia','evaluacion')}
    # Valores de reference_metrics.json del kit: ver FUENTES.md.
    for key, expected in dict(energy_it_kwh=35509.846, energy_total_kwh=45010.9549, water_l=13013.0147).items():
        assert isclose(splits['referencia'][key], expected, rel_tol=0, abs_tol=1e-6)
    site = [r for r in rows if r['site_id']=='SIM-B']
    ref = aggregate([r for r in site if r['split']=='referencia'])
    # scenario se usa solo para evaluar el contrafactual, nunca para detectar.
    leak = sorted([r for r in site if r['scenario']=='fuga_agua'], key=lambda r:r['timestamp'])
    excess = [max(0, float(r['water_l']) - ref['wue_captacion_l_kwh']*float(r['energy_it_kwh'])) for r in leak]
    # Resolución horaria: primer intervalo perdido; reparación hipotética antes del segundo.
    potential = sum(excess[1:])
    # Supuestos ilustrativos de despliegue continuo en UN sitio durante 168 horas.
    hours, monitor_w, facility_multiplier, water_intensity, carbon_kg = 168, 3, 1.3, 1, 0.3
    monitor_kwh = hours*monitor_w/1000
    added_facility_kwh = monitor_kwh*facility_multiplier
    added_water_l = added_facility_kwh*water_intensity
    result = dict(notice='DATOS SIMULADOS. Contrafactual y potencia supuestos; no ahorro real medido.',
        csv_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        full=aggregate(rows), by_split=splits,
        by_site={s:aggregate([r for r in rows if r['site_id']==s]) for s in sorted({r['site_id'] for r in rows})},
        water_scenario=dict(site='SIM-B', reference_wue=ref['wue_captacion_l_kwh'],
            leak_intervals=len(leak), leak_water_l=sum(float(r['water_l']) for r in leak),
            excess_all_8h_l=sum(excess), first_hour_unavoided_l=excess[0],
            avoidable_after_first_hour_l=potential,
            assumptions=dict(hours=hours, monitor_w=monitor_w, facility_multiplier=facility_multiplier,
                marginal_onsite_water_l_per_added_facility_kwh=water_intensity,
                carbon_kg_per_kwh=carbon_kg, teg_credit_kwh=0, avoided_process_energy_kwh=0),
            monitor_it_kwh=monitor_kwh, added_facility_kwh=added_facility_kwh,
            added_water_l=added_water_l, added_operational_carbon_kg=added_facility_kwh*carbon_kg,
            sensitivity=[dict(recovery_fraction=f, gross_avoided_l=potential*f,
                              net_avoided_l=potential*f-added_water_l) for f in (0,.25,.5,1)],
            break_even_recovery_fraction=added_water_l/potential))
    target=ROOT/'resultados.json'
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
