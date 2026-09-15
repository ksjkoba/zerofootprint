import os
import io
import json
import asyncio
import httpx
import torch
import torchvision.transforms as transforms
import torchvision.models as models
from datetime import datetime
from PIL import Image, ExifTags
from fastapi import FastAPI, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

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
        print(f"[!] Qdrant init: {e}")

# Dynamic Sherlock registry cache
SHERLOCK_REGISTRY = {}
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"

@app.on_event("startup")
async def load_sherlock_data():
    global SHERLOCK_REGISTRY
    ensure_collection()
    local_cache = "/app/sherlock_data.json"
    if os.path.exists(local_cache):
        try:
            with open(local_cache, "r", encoding="utf-8") as f:
                SHERLOCK_REGISTRY = json.load(f)
                return
        except Exception:
            pass

    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(SHERLOCK_URL, timeout=10.0)
            if res.status_code == 200:
                data = res.json()
                data.pop("$schema", None)
                SHERLOCK_REGISTRY = data
                with open(local_cache, "w", encoding="utf-8") as f:
                    json.dump(data, f)
    except Exception as e:
        print(f"[!] Sherlock ingestion fallback: {e}")

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

async def probe_sherlock(semaphore: asyncio.Semaphore, client: httpx.AsyncClient, name: str, site_data: dict, username: str):
    url = site_data.get("url", "").replace("{}", username)
    error_type = site_data.get("errorType", "status_code")
    error_msg = site_data.get("errorMsg", "")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeroFootprint/2.0"}

    async with semaphore:
        try:
            res = await client.get(url, headers=headers, timeout=4.5, follow_redirects=True)
            if error_type == "status_code":
                if res.status_code == 200:
                    return {"platform": name, "url": url}
            elif error_type == "message":
                if res.status_code == 200 and error_msg not in res.text:
                    return {"platform": name, "url": url}
            elif error_type == "response_url":
                if res.status_code == 200 and error_msg not in str(res.url):
                    return {"platform": name, "url": url}
        except Exception:
            pass
    return None

@app.post("/api/audit")
async def run_audit(username: str = Form(...), avatar: UploadFile = File(None)):
    ensure_collection()
    nodes = [{"data": {"id": username, "label": f"Target: {username}", "type": "root"}}]
    edges = []
    exif_findings = {}
    leak_matches = []

    # Controlled concurrency worker pool
    sem = asyncio.Semaphore(30)
    async with httpx.AsyncClient() as client:
        tasks = [probe_sherlock(sem, client, name, cfg, username) for name, cfg in SHERLOCK_REGISTRY.items()]
        results = await asyncio.gather(*tasks)

    exposed = [r for r in results if r]

    avatar_bytes = await avatar.read() if avatar else None

    # Graph construction
    for item in exposed:
        p_name = item["platform"]
        nodes.append({
            "data": {
                "id": p_name,
                "label": p_name,
                "type": "platform",
                "url": item["url"],
                "avatar_url": None
            }
        })
        edges.append({"data": {"source": username, "target": p_name, "label": "registered"}})

    # EXIF & Vector search
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
                print(f"[!] Qdrant matching error: {q_err}")

    score = min(100, (len(exposed) * 4) + (len(exif_findings) * 20) + (len(leak_matches) * 25))

    return JSONResponse({
        "target": username,
        "exposure_score": score,
        "exposure_count": len(exposed),
        "exif_leaks": exif_findings,
        "biometric_leaks": leak_matches,
        "platforms": [e["platform"] for e in exposed],
        "elements": {"nodes": nodes, "edges": edges}
    })

@app.post("/api/export-pdf")
async def generate_pdf(payload: dict):
    target = payload.get("target", "Target")
    score = payload.get("exposure_score", 0)
    exposure_count = payload.get("exposure_count", 0)
    exif_leaks = payload.get("exif_leaks", {})
    biometric_leaks = payload.get("biometric_leaks", [])
    platforms = payload.get("platforms", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    header_style = ParagraphStyle(
        'HeaderStyle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6
    )
    sub_style = ParagraphStyle(
        'SubStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14
    )
    section_style = ParagraphStyle(
        'SecStyle',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=8
    )

    story = []
    story.append(Paragraph("ZeroFootprint Attack Surface Audit Report", header_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Identity Target: <b>{target}</b>", sub_style))

    # Metric Summary Table
    risk_level = "CRITICAL" if score >= 70 else ("ELEVATED" if score >= 35 else "MINIMAL")
    score_data = [
        ["Metric", "Audit Finding"],
        ["Exposure Score", f"{score} / 100 ({risk_level})"],
        ["Discovered Public Endpoints", f"{exposure_count} exposed services"],
        ["EXIF Metadata Leaks", f"{len(exif_leaks)} attributes detected"],
        ["Cross-Profile Vector Leaks", f"{len(biometric_leaks)} identity correlations"]
    ]
    t_summary = Table(score_data, colWidths=[200, 340])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t_summary)

    # Exposed Platforms Table
    story.append(Paragraph("Exposed Profile Endpoints", section_style))
    p_data = [["Platform", "Registry Status"]]
    for p in platforms[:30]:
        p_data.append([p, "Active Public Profile Discovered"])
    if len(platforms) > 30:
        p_data.append([f"...and {len(platforms) - 30} more", "Truncated for document brevity"])
    if len(platforms) == 0:
        p_data.append(["None", "No public profile registrations discovered."])

    t_platforms = Table(p_data, colWidths=[200, 340])
    t_platforms.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t_platforms)

    # EXIF & Biometric Findings
    if exif_leaks or biometric_leaks:
        story.append(Paragraph("Telemetry & Identity Association Findings", section_style))
        leak_data = [["Leak Type", "Finding Details"]]
        for k, v in exif_leaks.items():
            leak_data.append([f"EXIF: {k}", str(v)])
        for b in biometric_leaks:
            leak_data.append(["Shared Avatar Vector", f"{b['username']} ({b['similarity']}% similarity)"])

        t_leaks = Table(leak_data, colWidths=[200, 340])
        t_leaks.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_leaks)

    story.append(Paragraph("Remediation Notice", section_style))
    story.append(Paragraph(
        "To exercise your statutory Right to Erasure under GDPR Article 17 and CCPA § 1798.105, "
        "send formal deletion requests to the respective Data Protection Officers of the exposed services.",
        sub_style
    ))

    doc.build(story)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ZeroFootprint_Report_{target}.pdf"}
    )

app.mount("/static", StaticFiles(directory="/app/frontend"), name="static")

@app.get("/")
def serve_ui():
    return FileResponse("/app/frontend/index.html")
