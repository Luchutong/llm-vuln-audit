"""White-box source audit: the run's durable state, its workers and its model drivers.

The package's first module, which is exactly why one line of process setup lives here:
``smolagents`` imports ``huggingface_hub`` at module level and the hub library reads its
telemetry switch as it is imported, so the switch has to be set before any submodule here
can import the agent library.  This run makes no external request of its own accord, and
saying so in code keeps that true regardless of how the process was started.
"""
import os

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
