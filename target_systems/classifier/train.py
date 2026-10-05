import torch
import torch.nn as nn
import torch.optim as optim
import os

class SimpleCNN(nn.Module):
    def __init__(self):
        super(SimpleCNN, self).__init__()
        self.conv1 = nn.Conv2d(1, 10, kernel_size=5)
        self.conv2 = nn.Conv2d(10, 20, kernel_size=5)
        self.fc1 = nn.Linear(320, 50)
        self.fc2 = nn.Linear(50, 10)

    def forward(self, x):
        import torch.nn.functional as F
        x = F.relu(F.max_pool2d(self.conv1(x), 2))
        x = F.relu(F.max_pool2d(self.conv2(x), 2))
        x = x.view(-1, 320)
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)

def train_model():
    model = SimpleCNN()
    optimizer = optim.SGD(model.parameters(), lr=0.01, momentum=0.5)
    
    # Fake training loop for quick setup
    print("Training dummy model...")
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    torch.save(model.state_dict(), os.path.join(os.path.dirname(__file__), "model.pth"))
    print("Model saved to model.pth")

if __name__ == "__main__":
    train_model()
