"""Read the already selected local model without printing or persisting credentials."""
import json,sqlite3,sys,urllib.request
from pathlib import Path
from cryptography.fernet import Fernet
R=Path(r'\\wsl.localhost\Ubuntu-24.04\home\luchitong\work\vuln-audit')

def selected_model():
    sys.path.insert(0,str(R/'backend'))
    from audit.config import ModelConfig
    with urllib.request.urlopen('http://127.0.0.1:8899/api/config',timeout=15) as response:public=json.load(response)
    # The UNC filesystem cannot coordinate POSIX SQLite locks with Windows. Read
    # the checkpointed main file immutably, then require the public API's selected
    # profile/model/endpoint to match before using it. Never edit the live database.
    db=sqlite3.connect(f'file://{R.as_posix()}/data/audit.db?mode=ro&immutable=1',uri=True);db.row_factory=sqlite3.Row
    row=db.execute('SELECT profile.* FROM model_selection AS selection JOIN model_profiles AS profile ON profile.id=selection.selected_profile_id WHERE selection.id=1').fetchone()
    if row is None:raise RuntimeError('No checkpointed selected model profile')
    profile=dict(row);db.close()
    if profile.get('credential_source')=='environment':
        from audit.config import load_env_file
        env=next((p for p in [R/'.env',R/'backend/.env'] if p.is_file()),None)
        if env is None:raise RuntimeError('Selected environment credential file unavailable')
        load_env_file(env);config=ModelConfig.from_environ()
    else:
        cipher=Fernet((R/'data/.model-config.key').read_bytes().strip())
        key=cipher.decrypt(profile['api_key_secret'].encode()).decode()
        config=ModelConfig(model=profile['model'],base_url=profile['base_url'],api_key=key,thinking=profile.get('thinking') or 'disabled')
    # API shape is versioned; compare explicit public active fields, never secrets.
    current=public.get('model')
    if not isinstance(current,dict):
        current=public.get('model_config') or public
    actual_name=current.get('model') or (public.get('model') if isinstance(public.get('model'),str) else '')
    actual_url=current.get('base_url') or public.get('base_url','')
    if actual_name and config.model!=actual_name:raise RuntimeError('Checkpointed model differs from active API model')
    if actual_url and config.public_base_url().rstrip('/')!=actual_url.rstrip('/'):raise RuntimeError('Checkpointed endpoint differs from active API endpoint')
    if not config.configured:raise RuntimeError('Selected model is not configured')
    return config,{'profile_id':profile['id'],'model':config.model,'base_url':config.public_base_url(),'thinking':config.thinking,'credential_persisted_in_evidence':False,'api_configuration_match':True}

if __name__=='__main__':
    _,public=selected_model();print(json.dumps(public,ensure_ascii=False))
