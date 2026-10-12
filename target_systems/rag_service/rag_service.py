import os

def query_rag(prompt: str) -> str:
    """Dummy RAG query."""
    doc_path = os.path.join(os.path.dirname(__file__), "sensitive_docs.txt")
    if os.path.exists(doc_path):
        with open(doc_path, "r") as f:
            docs = f.read()
    else:
        docs = ""
        
    if "key" in prompt.lower() or "password" in prompt.lower():
        return f"Based on docs: {docs}"
    return "Generic response."
