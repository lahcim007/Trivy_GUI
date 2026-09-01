from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

engine = create_engine(
    "sqlite:////data/trivy_gui.db",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def migrate():
    insp = inspect(engine)
    names = set(insp.get_table_names())
    if "scans" not in names:
        return
    cols = {c["name"] for c in insp.get_columns("scans")}
    stmts = []
    if "created_by" not in cols:
        stmts.append("ALTER TABLE scans ADD COLUMN created_by VARCHAR(64)")
    if not stmts:
        return
    with engine.begin() as conn:
        for s in stmts:
            conn.execute(text(s))