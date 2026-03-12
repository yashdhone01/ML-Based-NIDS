from flask import Flask, request, jsonify
from src.predict import NIDSEngine

app = Flask(__name__)
engine = NIDSEngine()  # load model once at startup

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        # support single dict or list of dicts
        if isinstance(data, list):
            result = engine.predict_batch(data)
        else:
            result = engine.predict(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'running', 'model': 'Random Forest IDS'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)