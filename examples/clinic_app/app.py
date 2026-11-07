"""A second, unrelated app, to show Mayajaal is not tied to the demo. All data here is made up.

Mayajaal needs two things from an app:
  1. A call to protect() inside a factory that accepts optional settings.
  2. A list of normal traffic: golden.json, next to this file.

Run it:
  $env:MAYAJAAL_TARGET_APP = "app:create_app"
  $env:MAYAJAAL_TARGET_GOLDEN = "golden.json"
  $env:MAYAJAAL_DECOYS_FILE = "decoys.json"     # Bait suggested by `mayajaal suggest-traps`, then reviewed.
  uvicorn --factory app:create_app --port 8000    # In this folder.
  mayajaal worker                                 # In this folder, in a second terminal.
  mayajaal dashboard                              # In a third.

Like the demo, it has a deliberate flaw: the export forgets to check who is asking."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from mayajaal import protect

NAMES = ["Priya Nair", "Rohan Gupta", "Farah Sheikh", "Anil Reddy", "Lakshmi Iyer"]
PATIENTS = [{"id": 100 + i, "name": name, "ward": "A"} for i, name in enumerate(NAMES)]


def create_app(settings=None) -> FastAPI:
    app = FastAPI(title="Clinic")
    protect(app, settings=settings, route_tags={
        "/patients": "data", "/patients/export": "data", "/patients/:id": "data",
    })

    @app.get("/")
    def home():
        return {"clinic": "Sunrise Clinic", "open": True}

    @app.get("/doctors")
    def doctors():
        return {"doctors": ["Dr. Meera Kulkarni", "Dr. Imran Qureshi"]}

    @app.get("/patients")
    def patients(ward: str = "A"):
        return {"patients": [p for p in PATIENTS if p["ward"] == ward]}

    @app.get("/patients/export")
    def export(limit: int = 10, format: str = "json"):  # DELIBERATE DEMO FLAW: no sign-in check.
        return {"format": format, "patients": PATIENTS[:limit]}

    @app.get("/patients/{patient_id}")
    def patient(patient_id: int):
        for item in PATIENTS:
            if item["id"] == patient_id:
                return item
        raise HTTPException(404, "Not found")

    return app
