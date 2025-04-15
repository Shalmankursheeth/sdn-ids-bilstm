# ml_bilstm.py
import tensorflow as tf
import json
import numpy as np

class BiLSTMModel:
    def __init__(self, config_path, weights_path):
        # Load the model architecture from config.json
        with open(config_path, 'r') as f:
            model_config = json.load(f)
        self.model = tf.keras.models.model_from_json(model_config)
        
        # Load the model weights from model.weights.h5
        self.model.load_weights(weights_path)

    def classify(self, features):
        # Ensure the input is in the shape the model expects
        features = np.array(features).reshape((1, len(features), 1))  # Adjust shape as per model requirements
        prediction = self.model.predict(features)
        return np.argmax(prediction)  # Assuming the model outputs probabilities for classes
