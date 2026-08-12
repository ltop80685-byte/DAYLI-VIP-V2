# -*- coding: utf-8 -*-
import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

# ------------------- التحميل والإعدادات -------------------
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key_change_me")
DEFAULT_DAYS = int(os.getenv("DEFAULT_DAYS", 30))
MAX_TRIAL_PER_IP = int(os.getenv("MAX_TRIAL_PER_IP", 3))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./licenses.db")

# ------------------- قاعدة البيانات -------------------
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class LicenseKey(Base):
    __tablename__ = "license_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_value = Column(String(128), unique=True, index=True, nullable=False)
    app_id = Column(String(64), index=True, nullable=False)
    machine_id = Column(String(128), nullable=True)
    max_activations = Column(Integer, default=1)
    used_count = Column(Integer, default=0)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    is_trial = Column(Boolean, default=False)
    metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class LicenseLog(Base):
    __tablename__ = "license_logs"
    id = Column(Integer, primary_key=True, index=True)
    key_id = Column(Integer, index=True, nullable=True)
    action = Column(String(32), nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(String(256))
    details = Column(JSON, default={})
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class TrialTracker(Base):
    __tablename__ = "trial_tracker"
    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String(128), unique=True, index=True)
    count = Column(Integer, default=1)
    first_trial_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

# ------------------- نماذج Pydantic (v1) -------------------
class KeyGenerateRequest(BaseModel):
    app_id: str = Field(..., example="my_app_v2")
    days_valid: int = Field(DEFAULT_DAYS, ge=1, example=30)
    max_activations: int = Field(1, ge=1, example=5)
    machine_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

    class Config:
        arbitrary_types_allowed = True

class KeyGenerateResponse(BaseModel):
    license_key: str
    expires_at: str
    app_id: str
    max_activations: int

class KeyVerifyRequest(BaseModel):
    license_key: str
    machine_id: Optional[str] = None
    app_id: Optional[str] = None

class KeyVerifyResponse(BaseModel):
    valid: bool
    reason: Optional[str] = None
    app_id: Optional[str] = None
    remaining_days: Optional[int] = None
    remaining_activations: Optional[int] = None
    expires_at: Optional[str] = None
    is_trial: Optional[bool] = None

class KeyFormatRequest(BaseModel):
    license_key: str
    format_type: str = Field("dashed", regex="^(dashed|uppercase|lowercase|raw)$")

class KeyExtendRequest(BaseModel):
    license_key: str
    extra_days: int = Field(..., ge=1)
    reset_usage: bool = False

class KeyBlockRequest(BaseModel):
    license_key: str
    reason: Optional[str] = None

class TrialRequest(BaseModel):
    app_id: str
    identifier: str

# ------------------- دوال مساعدة -------------------
def base62_encode(data: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    num = int.from_bytes(data, byteorder='big')
    if num == 0:
        return alphabet[0]
    result = []
    while num > 0:
        num, rem = divmod(num, 62)
        result.append(alphabet[rem])
    return ''.join(reversed(result))

def decode_base62(s: str) -> bytes:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    num = 0
    for ch in s:
        num = num * 62 + alphabet.index(ch)
    length = (num.bit_length() + 7) // 8
    if length == 0:
        return b'\x00'
    return num.to_bytes(length, byteorder='big')

def generate_license_key(app_id: str, days_valid: int, max_activations: int, is_trial: bool = False) -> tuple[str, datetime]:
    salt = secrets.token_bytes(8)
    expiry = datetime.now(timezone.utc) + timedelta(days=days_valid)
    expiry_ts = int(expiry.timestamp())
    payload = f"{app_id}:{expiry_ts}:{max_activations}:{salt.hex()}:{int(is_trial)}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()[:16]
    payload_bytes = payload.encode('utf-8')
    raw = bytes([2]) + bytes([len(payload_bytes)]) + payload_bytes + signature
    key_str = base62_encode(raw)
    return key_str, expiry

def parse_license_key(key_str: str) -> Optional[dict]:
    try:
        raw = decode_base62(key_str)
        if len(raw) < 3:
            return None
        version = raw[0]
        if version != 2:
            return None
        payload_len = raw[1]
        if len(raw) < 2 + payload_len + 16:
            return None
        payload_bytes = raw[2:2+payload_len]
        signature = raw[2+payload_len:2+payload_len+16]
        payload = payload_bytes.decode('utf-8')
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(signature, expected):
            return None
        parts = payload.split(':')
        if len(parts) != 5:
            return None
        app_id, expiry_ts, max_act, salt, is_trial = parts
        return {
            "app_id": app_id,
            "expiry_ts": int(expiry_ts),
            "max_activations": int(max_act),
            "salt": salt,
            "is_trial": is_trial == "1"
        }
    except Exception:
        return None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------- جدولة التنظيف التلقائي -------------------
scheduler = BackgroundScheduler()
@scheduler.scheduled_job('cron', hour=3, minute=0)
def clean_expired_keys():
    db = SessionLocal()
    try:
        expired = db.query(LicenseKey).filter(
            LicenseKey.expires_at < datetime.now(timezone.utc),
            LicenseKey.is_active == True
        ).all()
        for key in expired:
            key.is_active = False
            log = LicenseLog(
                key_id=key.id,
                action='auto_block',
                details={'reason': 'انتهت الصلاحية تلقائياً'}
            )
            db.add(log)
        db.commit()
    finally:
        db.close()
scheduler.start()

# ------------------- تطبيق FastAPI -------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.start()
    yield
    scheduler.shutdown()

app = FastAPI(title="نظام إدارة مفاتيح التفعيل API", version="2.2", lifespan=lifespan)

# ------------------- نقاط النهاية -------------------
@app.post("/api/v1/keys/generate", response_model=KeyGenerateResponse)
async def generate_key(req: KeyGenerateRequest, db: Session = Depends(get_db)):
    key_str, expires = generate_license_key(req.app_id, req.days_valid, req.max_activations)
    new_key = LicenseKey(
        key_value=key_str,
        app_id=req.app_id,
        machine_id=req.machine_id,
        max_activations=req.max_activations,
        expires_at=expires,
        metadata=req.metadata or {}
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    return KeyGenerateResponse(
        license_key=key_str,
        expires_at=expires.isoformat(),
        app_id=req.app_id,
        max_activations=req.max_activations
    )

@app.post("/api/v1/keys/verify", response_model=KeyVerifyResponse)
async def verify_key(req: KeyVerifyRequest, request: Request, db: Session = Depends(get_db)):
    parsed = parse_license_key(req.license_key)
    if not parsed:
        return KeyVerifyResponse(valid=False, reason="تنسيق المفتاح غير صحيح أو توقيع فاسد")
    if datetime.now(timezone.utc).timestamp() > parsed["expiry_ts"]:
        return KeyVerifyResponse(valid=False, reason="انتهت صلاحية المفتاح")
    db_key = db.query(LicenseKey).filter(LicenseKey.key_value == req.license_key).first()
    if not db_key:
        return KeyVerifyResponse(valid=False, reason="المفتاح غير مسجل في النظام")
    if not db_key.is_active:
        return KeyVerifyResponse(valid=False, reason="المفتاح محظور")
    if db_key.used_count >= db_key.max_activations:
        return KeyVerifyResponse(valid=False, reason="تم استنفاد عدد مرات التفعيل المسموح بها")
    if db_key.machine_id and req.machine_id and db_key.machine_id != req.machine_id:
        return KeyVerifyResponse(valid=False, reason="المفتاح مقيد بجهاز آخر")
    if req.app_id and db_key.app_id != req.app_id:
        return KeyVerifyResponse(valid=False, reason="المفتاح غير مخصص لهذا التطبيق")
    db_key.used_count += 1
    db.add(db_key)
    log = LicenseLog(
        key_id=db_key.id,
        action='check',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        details={'machine_id': req.machine_id}
    )
    db.add(log)
    db.commit()
    remaining_days = (db_key.expires_at - datetime.now(timezone.utc)).days
    return KeyVerifyResponse(
        valid=True,
        app_id=db_key.app_id,
        remaining_days=remaining_days,
        remaining_activations=db_key.max_activations - db_key.used_count,
        expires_at=db_key.expires_at.isoformat(),
        is_trial=db_key.is_trial
    )

@app.post("/api/v1/keys/format")
async def format_key(req: KeyFormatRequest):
    key = req.license_key
    if req.format_type == "uppercase":
        return {"formatted_key": key.upper()}
    elif req.format_type == "lowercase":
        return {"formatted_key": key.lower()}
    elif req.format_type == "dashed":
        parts = [key[i:i+4] for i in range(0, len(key), 4)]
        return {"formatted_key": "-".join(parts)}
    else:
        return {"formatted_key": key}

@app.post("/api/v1/keys/extend")
async def extend_key(req: KeyExtendRequest, request: Request, db: Session = Depends(get_db)):
    db_key = db.query(LicenseKey).filter(LicenseKey.key_value == req.license_key).first()
    if not db_key:
        raise HTTPException(status_code=404, detail="المفتاح غير موجود")
    if not db_key.is_active:
        raise HTTPException(status_code=400, detail="المفتاح محظور ولا يمكن تمديده")
    new_expiry = db_key.expires_at + timedelta(days=req.extra_days)
    db_key.expires_at = new_expiry
    if req.reset_usage:
        db_key.used_count = 0
    db.add(db_key)
    log = LicenseLog(
        key_id=db_key.id,
        action='extend',
        ip_address=request.client.host,
        details={'extra_days': req.extra_days, 'reset_usage': req.reset_usage}
    )
    db.add(log)
    db.commit()
    return {
        "success": True,
        "new_expires_at": new_expiry.isoformat(),
        "remaining_days": (new_expiry - datetime.now(timezone.utc)).days
    }

@app.post("/api/v1/keys/block")
async def block_key(req: KeyBlockRequest, request: Request, db: Session = Depends(get_db)):
    db_key = db.query(LicenseKey).filter(LicenseKey.key_value == req.license_key).first()
    if not db_key:
        raise HTTPException(status_code=404, detail="المفتاح غير موجود")
    if not db_key.is_active:
        return {"success": True, "message": "المفتاح محظور بالفعل"}
    db_key.is_active = False
    db.add(db_key)
    log = LicenseLog(
        key_id=db_key.id,
        action='block',
        ip_address=request.client.host,
        details={'reason': req.reason}
    )
    db.add(log)
    db.commit()
    return {"success": True, "message": "تم حظر المفتاح بنجاح"}

@app.post("/api/v1/trial/generate")
async def generate_trial(req: TrialRequest, request: Request, db: Session = Depends(get_db)):
    tracker = db.query(TrialTracker).filter(TrialTracker.identifier == req.identifier).first()
    if tracker and tracker.count >= MAX_TRIAL_PER_IP:
        raise HTTPException(status_code=429, detail=f"تجاوزت الحد الأقصى للمحاولات التجريبية ({MAX_TRIAL_PER_IP})")
    key_str, expires = generate_license_key(req.app_id, days_valid=7, max_activations=1, is_trial=True)
    new_key = LicenseKey(
        key_value=key_str,
        app_id=req.app_id,
        max_activations=1,
        expires_at=expires,
        is_trial=True,
        metadata={'trial_identifier': req.identifier}
    )
    db.add(new_key)
    if tracker:
        tracker.count += 1
    else:
        tracker = TrialTracker(identifier=req.identifier, count=1)
        db.add(tracker)
    db.commit()
    return {
        "license_key": key_str,
        "expires_at": expires.isoformat(),
        "trial_days": 7,
        "remaining_trials": MAX_TRIAL_PER_IP - (tracker.count if tracker else 1)
    }

@app.get("/api/v1/keys/list")
async def list_keys(app_id: Optional[str] = None, active_only: bool = True, db: Session = Depends(get_db)):
    query = db.query(LicenseKey)
    if app_id:
        query = query.filter(LicenseKey.app_id == app_id)
    if active_only:
        query = query.filter(LicenseKey.is_active == True)
    keys = query.all()
    result = []
    for k in keys:
        result.append({
            "key": k.key_value[:12] + "..." if len(k.key_value) > 12 else k.key_value,
            "app_id": k.app_id,
            "expires_at": k.expires_at.isoformat(),
            "used": f"{k.used_count}/{k.max_activations}",
            "active": k.is_active,
            "is_trial": k.is_trial,
            "created_at": k.created_at.isoformat()
        })
    return {"count": len(result), "keys": result}

@app.get("/api/v1/logs")
async def get_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(LicenseLog).order_by(LicenseLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "action": log.action,
            "timestamp": log.timestamp.isoformat(),
            "ip": log.ip_address,
            "details": log.details
        }
        for log in logs
    ]

@app.get("/health")
async def health_check():
    return {"status": "running", "version": "2.2"}

# ------------------- التشغيل -------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
