from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

db = Chroma(
    persist_directory="../vector_db",
    embedding_function=embedding
)

while True:
    question = input("\nAsk a question (type 'exit' to quit): ")

    if question.lower() == "exit":
        break

    results = db.similarity_search(question, k=3)

    print("\nTop Results:\n")

    for i, doc in enumerate(results, start=1):
        print(f"Result {i}")
        print(doc.page_content)
        print("-" * 60)