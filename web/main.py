"""
Wrapper web (FastAPI) para pwned_checker.
No modifica la lógica CLI existente — solo la expone vía HTTP.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Permite importar el paquete src/pwned_checker sin instalarlo
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from pwned_checker.checker import check_breach, hash_password
from pwned_checker.generator import GeneratorOptions, generate_password

app = FastAPI(
    title="Pwned-PassChecker API",
    description="Verificador de contraseñas comprometidas (HIBP k-Anonymity) + generador seguro.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


class CheckRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


class CheckResponse(BaseModel):
    status: str
    breach_count: int
    sha1_prefix: str
    sha1_suffix_masked: str


class GenerateRequest(BaseModel):
    length: int = Field(default=14, ge=8, le=128)
    use_digits: bool = True
    use_symbols: bool = True
    use_upper: bool = True
    use_lower: bool = True
    exclude_ambiguous: bool = False


class GenerateResponse(BaseModel):
    password: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    result = check_breach(req.password)

    if result.status.value == "error":
        raise HTTPException(status_code=502, detail="Error consultando la API de HIBP.")

    sha1 = hash_password(req.password)
    return CheckResponse(
        status=result.status.value,
        breach_count=result.breach_count,
        sha1_prefix=sha1[:5],
        sha1_suffix_masked=sha1[5:8] + "…" + sha1[-4:],
    )


@app.post("/generate", response_model=GenerateResponse)
def generate(req: GenerateRequest) -> GenerateResponse:
    try:
        opts = GeneratorOptions(
            length=req.length,
            use_digits=req.use_digits,
            use_symbols=req.use_symbols,
            use_upper=req.use_upper,
            use_lower=req.use_lower,
            exclude_ambiguous=req.exclude_ambiguous,
        )
        pwd = generate_password(opts)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return GenerateResponse(password=pwd)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
