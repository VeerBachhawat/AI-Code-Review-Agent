import os
import shutil
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

# Absolute paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DOCS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "documents"))
VECTOR_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "vector_db"))

print(f"Loading PDFs from: {DOCS_DIR}")
loader = PyPDFDirectoryLoader(DOCS_DIR)
documents = loader.load()

print(f"Loaded {len(documents)} pages")

# Clean metadata source filenames (e.g. fix Java_Secure_Coding_Guidelines.pdf.pdf)
for doc in documents:
    if "source" in doc.metadata:
        src = doc.metadata["source"]
        if src.endswith(".pdf.pdf"):
            doc.metadata["source"] = src[:-4]

# Split into chunks
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=100
)

chunks = text_splitter.split_documents(documents)

# Deduplicate identical chunks
unique_chunks = []
seen_content = set()
for c in chunks:
    content_key = c.page_content.strip()
    if content_key not in seen_content:
        seen_content.add(content_key)
        unique_chunks.append(c)

print(f"Created {len(chunks)} total chunks, deduplicated to {len(unique_chunks)} unique chunks")

# Remove existing vector DB directory to eliminate stored duplicates
if os.path.exists(VECTOR_DIR):
    print(f"Clearing existing vector DB at: {VECTOR_DIR}")
    shutil.rmtree(VECTOR_DIR)

# Create embeddings
embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

# Store vectors in ChromaDB
db = Chroma.from_documents(
    documents=unique_chunks,
    embedding=embedding,
    persist_directory=VECTOR_DIR
)

print("Knowledge Base Created Successfully!")