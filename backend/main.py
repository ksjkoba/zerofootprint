import os
import io
import asyncio
import httpx
import torch
import torchvision.transforms as transforms
import torchvision.models as models
from PIL import Image, ExifTags
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

app = FastAPI(title="ZeroFootprint Production Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant")
qclient = QdrantClient(host=QDRANT_HOST, port=6333)
COLLECTION_NAME = "profile_vectors"

device = torch.device("cpu")
model = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
model.fc = torch.nn.Identity()
model.eval()
model.to(device)

preprocess = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

def ensure_collection():
    try:
        cols = [c.name for c in qclient.get_collections().collections]
        if COLLECTION_NAME not in cols:
            qclient.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=qmodels.VectorParams(size=512, distance=qmodels.Distance.COSINE),
            )
    except Exception as e:
        print(f"[!] Qdrant init error: {e}")

def extract_exif(image_bytes: bytes) -> dict:
    leaks = {}
    try:
        image = Image.open(io.BytesIO(image_bytes))
        raw_exif = image._getexif()
        if raw_exif:
            for tag_id, val in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                if tag_name in ["Make", "Model", "Software", "DateTimeOriginal"]:
                    leaks[str(tag_name)] = str(val).strip()
                elif tag_name == "GPSInfo":
                    leaks["GPS_Location"] = "Embedded GPS Coordinates Present"
    except Exception:
        pass
    return leaks

def extract_embedding(image_bytes: bytes) -> list[float]:
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        tensor = preprocess(image).unsqueeze(0).to(device)
        with torch.no_grad():
            embedding = model(tensor).squeeze().cpu().numpy()
        norm = (embedding ** 2).sum() ** 0.5
        return (embedding / norm).tolist() if norm > 0 else []
    except Exception:
        return []

REGISTRY = {
    "GitHub": {"url": "https://api.github.com/users/{}", "type": "api", "avatar": "avatar_url", "profile": "https://github.com/{}"},
    "GitLab": {"url": "https://gitlab.com/api/v4/users?username={}", "type": "api_list", "avatar": "avatar_url", "profile": "https://gitlab.com/{}"},
    "Reddit": {"url": "https://www.reddit.com/user/{}/about.json", "type": "api", "avatar": "icon_img", "profile": "https://reddit.com/user/{}"},
    "DevTo": {"url": "https://dev.to/api/users/by_username?url={}", "type": "api", "avatar": "profile_image", "profile": "https://dev.to/{}"},
    "DockerHub": {"url": "https://hub.docker.com/v2/users/{}/", "type": "api", "avatar": None, "profile": "https://hub.docker.com/u/{}"},
    "HackerNews": {"url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "type": "api", "avatar": None, "profile": "https://news.ycombinator.com/user?id={}"},
    "Keybase": {"url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "type": "keybase", "avatar": None, "profile": "https://keybase.io/{}"},
    "PyPI": {"url": "https://pypi.org/user/{}/", "type": "http", "avatar": None, "profile": "https://pypi.org/user/{}/"}
}

async def probe_service(client: httpx.AsyncClient, name: str, cfg: dict, username: str):
    target_url = cfg["url"].format(username)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        res = await client.get(target_url, headers=headers, timeout=5.0, follow_redirects=True)
        if res.status_code == 200:
            avatar_url = None
            if cfg["type"] == "api":
                data = res.json()
                if cfg.get("avatar"):
                    avatar_url = data.get(cfg["avatar"])
            elif cfg["type"] == "api_list":
                data = res.json()
                if isinstance(data, list) and len(data) > 0 and cfg.get("avatar"):
                    avatar_url = data[0].get(cfg["avatar"])

            if avatar_url and "?" in avatar_url and "reddit" in avatar_url:
                avatar_url = avatar_url.split("?")[0]

            return {
                "platform": name,
                "profile_url": cfg["profile"].format(username),
                "avatar_url": avatar_url
            }
    except Exception:
        pass
    return None

@app.post("/api/audit")
async def run_audit(username: str = Form(...), avatar: UploadFile = File(None)):
    try:
        ensure_collection()
        nodes = [{"data": {"id": username, "label": f"Target: {username}", "type": "root"}}]
        edges = []
        exif_findings = {}
        leak_matches = []

        # 1. Parallel platform reconnaissance
        async with httpx.AsyncClient() as client:
            tasks = [probe_service(client, name, cfg, username) for name, cfg in REGISTRY.items()]
            results = await asyncio.gather(*tasks)

        exposed = [r for r in results if r]

        # 2. Avatar extraction
        avatar_bytes = await avatar.read() if avatar else None

        async with httpx.AsyncClient() as img_client:
            for item in exposed:
                p_name = item["platform"]
                nodes.append({
                    "data": {
                        "id": p_name,
                        "label": p_name,
                        "type": "platform",
                        "url": item["profile_url"],
                        "avatar_url": item.get("avatar_url")
                    }
                })
                edges.append({"data": {"source": username, "target": p_name, "label": "registered"}})

                if not avatar_bytes and item.get("avatar_url"):
                    try:
                        img_res = await img_client.get(item["avatar_url"], timeout=5.0, follow_redirects=True)
                        if img_res.status_code == 200:
                            avatar_bytes = img_res.content
                    except Exception:
                        pass

        # 3. EXIF analysis and vector search
        if avatar_bytes:
            exif_findings = extract_exif(avatar_bytes)
            for k, v in exif_findings.items():
                meta_id = f"meta_{k}"
                nodes.append({"data": {"id": meta_id, "label": f"{k}: {v}", "type": "meta", "detail": f"{k}: {v}"}})
                edges.append({"data": {"source": username, "target": meta_id, "label": "exposes_exif"}})

            vector = extract_embedding(avatar_bytes)
            if vector:
                point_id = abs(hash(username)) % 10000000
                try:
                    qclient.upsert(
                        collection_name=COLLECTION_NAME,
                        points=[qmodels.PointStruct(id=point_id, vector=vector, payload={"username": username})]
                    )

                    matches = qclient.search(collection_name=COLLECTION_NAME, query_vector=vector, limit=8)
                    for m in matches:
                        matched_user = m.payload.get("username") if m.payload else None
                        if matched_user and matched_user != username and m.score > 0.85:
                            leak_id = f"leak_{matched_user}"
                            leak_matches.append({"username": matched_user, "similarity": round(m.score * 100, 1)})
                            nodes.append({
                                "data": {
                                    "id": leak_id,
                                    "label": f"Shared Identity: {matched_user} ({int(m.score * 100)}%)",
                                    "type": "leak"
                                }
                            })
                            edges.append({"data": {"source": username, "target": leak_id, "label": "biometric_match"}})
                except Exception as q_err:
                    print(f"[!] Qdrant query bypassed: {q_err}")

        score = min(100, (len(exposed) * 8) + (len(exif_findings) * 20) + (len(leak_matches) * 25))

        return JSONResponse({
            "target": username,
            "exposure_score": score,
            "exposure_count": len(exposed),
            "exif_leaks": exif_findings,
            "biometric_leaks": leak_matches,
            "elements": {"nodes": nodes, "edges": edges}
        })

    except Exception as general_err:
        return JSONResponse(
            status_code=500,
            content={"error": str(general_err)}
        )

app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")

@app.get("/")
def serve_ui():
    return FileResponse("/app/frontend/index.html")
