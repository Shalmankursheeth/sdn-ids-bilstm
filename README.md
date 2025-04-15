# SDN Intrusion Detection System using BiLSTM

This project presents an Intrusion Detection System (IDS) tailored for Software Defined Networks (SDN) using a BiLSTM-based deep learning model. It includes traffic simulation, model training, attack detection, and real-time classification via the Ryu controller.

## 📁 Folder Structure

- `scripts/`  
  Contains core Python scripts for:
  - Topology creation (`topology.py`)
  - Ryu controller logic (`app.py`)
  - Attack simulations (`synattack.py`, `hpingtest.sh`)
  - Model testing and evaluation (`test.py`)
  - BiLSTM model training script

- `dataset/`  
  Includes the dataset used for training and testing the BiLSTM model (zipped for easy access).

- `paper/`  
  Contains the revised IEEE-format research paper presented and published, along with presentation slides and certificate (if applicable).

## 🧠 Model

- `first.keras` and `test3.keras`  
  Pretrained BiLSTM models built using Keras, specifically trained for SDN-based traffic anomaly detection.

## ⚙️ Requirements

- Python 3.8+
- TensorFlow / Keras
- Ryu Controller
- Mininet
- scapy, hping3 (for traffic simulation)
- Other dependencies listed inside the scripts

## 🚀 Running the Project

1. **Topology**  
   Launch the SDN topology:

       sudo python3 scripts/topology.py
   
2. **Controller (Ryu)**
    Start the Ryu controller:
   
        ryu-manager scripts/app.py

3.Simulate Attacks
    Run traffic simulation scripts (e.g., SYN flood):
      
      sudo bash scripts/hpingtest.sh

4.Model Testing
    Evaluate the BiLSTM model:

      python3 scripts/test.py

📊 Results
The project includes results from testing multiple attack scenarios, showcasing detection accuracy and false positive rates. More details are inside the research paper under /paper.

📜 License
For educational and research use only.
   
