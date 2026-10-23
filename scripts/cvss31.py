"""Compatibility entry point for the shared, dependency-free CVSS 3.1 engine."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from audit.cvss31 import BASE, VALUES, assessment, base_score, parse_vector, roundup, score_value, severity

__all__ = ['BASE', 'VALUES', 'assessment', 'base_score', 'parse_vector', 'roundup', 'score_value', 'severity']
