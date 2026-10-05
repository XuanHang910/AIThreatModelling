import torch
from .train import SimpleCNN
import os

def load_model():
    model = SimpleCNN()
    model_path = os.path.join(os.path.dirname(__file__), "model.pth")
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path))
    model.eval()
    return model

def predict(model, tensor_input):
    with torch.no_grad():
        output = model(tensor_input)
        return output.argmax(dim=1).item()
