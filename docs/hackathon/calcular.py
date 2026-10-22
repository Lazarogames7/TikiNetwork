"""Análisis reproducible del kit CIFOX. Solo stdlib. No conecta redes ni equipos OT."""
import csv
import hashlib
import json
from decimal import Decimal, ROUND_HALF_EVEN
from pathlib import Path
from math import isclose

ROOT = Path(__file__).resolve().parent
PRECISION = Decimal('0.000000000001')

def normalized(value):
    """Normaliza resultados para obtener el mismo JSON en distintas versiones de Python."""
    return float(value.quantize(PRECISION, rounding=ROUND_HALF_EVEN))

def aggregate(rows):
    it = sum((Decimal(r['energy_it_kwh']) for r in rows), Decimal(0))
    total = sum((Decimal(r['energy_total_kwh']) for r in rows), Decimal(0))
    water = sum((Decimal(r['water_l']) for r in rows), Decimal(0))
    return dict(rows=len(rows), energy_it_kwh=normalized(it),
                energy_total_kwh=normalized(total), water_l=normalized(water),
                pue=normalized(total/it) if it else None,
                wue_captacion_l_kwh=normalized(water/it) if it else None)

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
    reference_wue = Decimal(str(ref['wue_captacion_l_kwh']))
    excess = [max(Decimal(0), Decimal(r['water_l']) - reference_wue*Decimal(r['energy_it_kwh'])) for r in leak]
    # Resolución horaria: primer intervalo perdido; reparación hipotética antes del segundo.
    potential = sum(excess[1:], Decimal(0))
    # Supuestos ilustrativos de despliegue continuo en UN sitio durante 168 horas.
    hours, monitor_w = 168, 3
    facility_multiplier, water_intensity, carbon_kg = Decimal('1.3'), Decimal(1), Decimal('0.3')
    monitor_kwh = Decimal(hours*monitor_w)/Decimal(1000)
    added_facility_kwh = monitor_kwh*facility_multiplier
    added_water_l = added_facility_kwh*water_intensity
    result = dict(notice='DATOS SIMULADOS. Contrafactual y potencia supuestos; no ahorro real medido.',
        csv_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        full=aggregate(rows), by_split=splits,
        by_site={s:aggregate([r for r in rows if r['site_id']==s]) for s in sorted({r['site_id'] for r in rows})},
        water_scenario=dict(site='SIM-B', reference_wue=normalized(reference_wue),
            leak_intervals=len(leak), leak_water_l=normalized(sum((Decimal(r['water_l']) for r in leak), Decimal(0))),
            excess_all_8h_l=normalized(sum(excess, Decimal(0))), first_hour_unavoided_l=normalized(excess[0]),
            avoidable_after_first_hour_l=normalized(potential),
            assumptions=dict(hours=hours, monitor_w=monitor_w, facility_multiplier=float(facility_multiplier),
                marginal_onsite_water_l_per_added_facility_kwh=float(water_intensity),
                carbon_kg_per_kwh=float(carbon_kg), teg_credit_kwh=0, avoided_process_energy_kwh=0),
            monitor_it_kwh=normalized(monitor_kwh), added_facility_kwh=normalized(added_facility_kwh),
            added_water_l=normalized(added_water_l), added_operational_carbon_kg=normalized(added_facility_kwh*carbon_kg),
            sensitivity=[dict(recovery_fraction=float(f), gross_avoided_l=normalized(potential*f),
                              net_avoided_l=normalized(potential*f-added_water_l))
                         for f in (Decimal(0), Decimal('.25'), Decimal('.5'), Decimal(1))],
            break_even_recovery_fraction=normalized(added_water_l/potential)))
    target=ROOT/'resultados.json'
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
