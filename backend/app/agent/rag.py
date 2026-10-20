"""Regulation knowledge base: public guidance PDFs -> Chroma vector store.

Put PDFs in data/guidance/ (e.g. FINTRAC STR guidance, FATF red-flag
indicators for money laundering and virtual assets), then run
scripts/build_rag_index.py.
"""
import glob
import os
import chromadb
from pypdf import PdfReader
from app import config

_col = None


def _collection():
    """Opened on first use, not at import, so the API starts even before the index exists."""
    global _col
    if _col is None:
        client = chromadb.PersistentClient(path=config.CHROMA_PATH)
        _col = client.get_or_create_collection("guidance")  # default local embedding model
    return _col


def build(folder="data/guidance", chunk=900, overlap=150):
    ids, docs, metas = [], [], []
    for path in glob.glob(f"{folder}/*.pdf"):
        name = os.path.basename(path)
        for pno, page in enumerate(PdfReader(path).pages, start=1):
            text = " ".join((page.extract_text() or "").split())
            for i in range(0, len(text), chunk - overlap):
                piece = text[i:i + chunk]
                if len(piece) > 200:
                    ids.append(f"{name}-{pno}-{i}"); docs.append(piece)
                    metas.append({"source": name, "page": pno})
    for i in range(0, len(ids), 200):
        _collection().upsert(ids=ids[i:i+200], documents=docs[i:i+200], metadatas=metas[i:i+200])
    return len(ids)


def retrieve(query: str, k: int = 4) -> list[dict]:
    res = _collection().query(query_texts=[query], n_results=k)
    return [{"ref": n + 1, "text": d, **m}
            for n, (d, m) in enumerate(zip(res["documents"][0], res["metadatas"][0]))]
