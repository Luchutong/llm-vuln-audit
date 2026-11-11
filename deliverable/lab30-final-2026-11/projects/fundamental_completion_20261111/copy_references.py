"""Copy the exact frozen inputs used by the new offline analyses; no re-creation."""
import hashlib,json,shutil
from pathlib import Path
P=Path(__file__).resolve().parent;R=P/'references';R.mkdir(exist_ok=True)
FILES={
 'source.zip':'closure_evidence_20261111/inputs/dataset/lab30-shop-1.0.0-source.zip',
 'ground_truth.json':'closure_evidence_20261111/inputs/dataset/ground_truth.json',
 'anchors.json':'closure_evidence_20261111/inputs/dataset/scoring_anchors_v2.json',
 'old_score.json':'closure_evidence_20261111/scores/old.json',
 'new_score.json':'closure_evidence_20261111/scores/new.json',
 'old_findings.json':'closure_evidence_20261111/inputs/old/findings.json',
 'input_identity.json':'closure_evidence_20261111/provenance/input_identity.json',
 'baseline_report.json':'e_paired_retry_20261111/paired_results/baseline_report.redacted.json',
 'injected_report.json':'e_paired_retry_20261111/paired_results/injected_report.redacted.json',
 'injected_supplement_report.json':'e_supplement_check_20261111/paired_results/injected_report.redacted.json',
 'baseline_full.zip':'e_materials_20261111/baseline_full.zip',
 'injected_full.zip':'e_materials_20261111/injected_full.zip',
 'samples_manifest.json':'e_materials_20261111/samples_manifest.json',
 'invalid_reference_controls.json':'material_completion_20261109/证据行号校验_受控试验.json',
 'schemas_collection_checkout.py':'b_materials_fix_20261109/backend/audit/schemas.py',
 'role_policy_collection_checkout.py':'b_materials_fix_20261109/backend/audit/role_policy.py'}
manifest=[]
for name,source in FILES.items():
    src=P.parent/source;dst=R/name;shutil.copyfile(src,dst)
    manifest.append({'path':name,'upstream':str(src),'sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),'bytes':dst.stat().st_size})
(R/'provenance.json').write_text(json.dumps({'files':manifest,'code_reference_note':'The Windows checkout schema is a collection-time reference, not a claim it exactly matches every historical running worktree. Actual historical host rejection records are primary evidence.'},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'copied':len(manifest)},ensure_ascii=False))
