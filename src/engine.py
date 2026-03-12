# src/engine.py
# This is the public API of the NIDS engine
# Anyone can import this and use it directly:
#
#   from src.engine import NIDSEngine
#   engine = NIDSEngine()
#   result = engine.predict({...})

from src.predict import NIDSEngine

__all__ = ['NIDSEngine']