# example.py
# Quick example showing how to use the NIDS engine
# Run: python example.py

from src.engine import NIDSEngine

engine = NIDSEngine()

# Single prediction
result = engine.predict({
    'duration': 0,
    'protocol_type': 1,
    'service': 21,
    'flag': 10,
    'src_bytes': 491,
    'dst_bytes': 0,
    'land': 0,
    'wrong_fragment': 0,
    'urgent': 0,
    'hot': 0,
    'num_failed_logins': 0,
    'logged_in': 0,
    'num_compromised': 0,
    'count': 2,
    'srv_count': 2
})
print("Single prediction:", result)

# Batch prediction
batch = [
    {'src_bytes': 491, 'dst_bytes': 0},    # likely DoS
    {'src_bytes': 0,   'dst_bytes': 1000},  # likely Normal
]
results = engine.predict_batch(batch)
print("\nBatch predictions:")
for r in results:
    print(f"  {r['prediction']} ({r['confidence']*100:.1f}%) → {r['status']}")