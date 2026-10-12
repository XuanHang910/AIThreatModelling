import os

def setup_dummy_rag():
    print("Setting up dummy RAG service with fake sensitive documents...")
    # Setup chroma db or dummy files
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "sensitive_docs.txt"), "w") as f:
        f.write("Secret API Key: 12345-ABCDE\n")
        f.write("Admin Password: super_secret_password\n")
    print("RAG setup complete.")

if __name__ == "__main__":
    setup_dummy_rag()
