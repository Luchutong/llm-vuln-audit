"""Fence business writes from interpreter threads after a run changes owner."""
from functools import wraps
from inspect import signature

from .execution_state import CURRENT_EXECUTION

MUTATIONS = {
    "merge_project_finding", "record_carried_findings", "set_project_finding_disposition",
    "link_finding_project", "set_finding_verification_state", "set_project_finding_verification",
    "mark_unit_running", "checkpoint_unit", "finish_unit", "claim_next_task_work", "resolve_task_work",
    "settle_task_goal_if_idle", "record_investigation", "set_investigation_status", "begin_planner_round",
    "finish_planner_round", "apply_plan", "claim_ready_task", "resolve_task_attempt", "add_finding",
    "set_finding_disposition", "set_finding_verdict", "record_automatic_verification", "add_verification",
    "add_poc_verification_job", "add_attribution",
}

def install_execution_guards(cls):
    for name in MUTATIONS:
        original = getattr(cls, name)
        spec = signature(original)

        @wraps(original)
        def guarded(self, *args, _method=original, _spec=spec, **kwargs):
            context = CURRENT_EXECUTION.get()
            if context is None:
                return _method(self, *args, **kwargs)
            with self._lock:
                self.assert_execution_write(context.run_id)
                values = _spec.bind(self, *args, **kwargs).arguments
                run_id = values.get("run_id")
                for field in ("record", "finding", "job"):
                    if isinstance(values.get(field), dict):
                        run_id = values[field].get("run_id", run_id)
                for key, table in (("task_id", "planner_tasks"), ("work_id", "task_work_items"), ("finding_id", "findings"), ("investigation_id", "planner_investigations")):
                    if values.get(key):
                        row = self._db.execute(f"SELECT run_id FROM {table} WHERE id=?", (values[key],)).fetchone()
                        if row:
                            run_id = row["run_id"]
                if run_id is not None:
                    self.assert_execution_write(run_id)
                return _method(self, *args, **kwargs)
        setattr(cls, name, guarded)
