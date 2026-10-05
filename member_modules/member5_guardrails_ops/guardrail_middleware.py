import re

class Guardrail:
    def __init__(self):
        self.block_patterns = [re.compile(r"api key", re.IGNORECASE), re.compile(r"password", re.IGNORECASE)]
        
    def check_input(self, text: str) -> bool:
        for p in self.block_patterns:
            if p.search(text):
                return False
        return True
