"""Report builder — deliberately long so a finding hides deep in the file."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request

from .db import db

router = APIRouter()
log = logging.getLogger(__name__)

def _format_block_1(rows: list[dict]) -> str:
    """Render block 1 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k1", ""), row.get("v1", 0)))
    return "\n".join(out)

def _format_block_2(rows: list[dict]) -> str:
    """Render block 2 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k2", ""), row.get("v2", 0)))
    return "\n".join(out)

def _format_block_3(rows: list[dict]) -> str:
    """Render block 3 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k3", ""), row.get("v3", 0)))
    return "\n".join(out)

def _format_block_4(rows: list[dict]) -> str:
    """Render block 4 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k4", ""), row.get("v4", 0)))
    return "\n".join(out)

def _format_block_5(rows: list[dict]) -> str:
    """Render block 5 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k5", ""), row.get("v5", 0)))
    return "\n".join(out)

def _format_block_6(rows: list[dict]) -> str:
    """Render block 6 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k6", ""), row.get("v6", 0)))
    return "\n".join(out)

def _format_block_7(rows: list[dict]) -> str:
    """Render block 7 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k7", ""), row.get("v7", 0)))
    return "\n".join(out)

def _format_block_8(rows: list[dict]) -> str:
    """Render block 8 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k8", ""), row.get("v8", 0)))
    return "\n".join(out)

def _format_block_9(rows: list[dict]) -> str:
    """Render block 9 of the monthly report."""
    out = []
    for row in rows:
        out.append("| {:<12} | {:>10} |".format(row.get("k9", ""), row.get("v9", 0)))
    return "\n".join(out)

@router.get("/reports/monthly")
async def monthly(request: Request, user=Depends(get_current_user)):
    """Build the monthly report for the current tenant."""
    table = request.query_params.get("table", "orders")
    rows = await db.execute(f"SELECT * FROM {table} WHERE tenant_id = {user.tenant_id}")
    log.info("report built for %s", user.tenant_id)
    return {"blocks": rows}

def _summarise_1(rows: list[dict]) -> dict:
    """Aggregate column 1."""
    total = sum(int(r.get("v1", 0)) for r in rows)
    return {"sum_1": total, "rows": len(rows)}

def _summarise_2(rows: list[dict]) -> dict:
    """Aggregate column 2."""
    total = sum(int(r.get("v2", 0)) for r in rows)
    return {"sum_2": total, "rows": len(rows)}

def _summarise_3(rows: list[dict]) -> dict:
    """Aggregate column 3."""
    total = sum(int(r.get("v3", 0)) for r in rows)
    return {"sum_3": total, "rows": len(rows)}

def _summarise_4(rows: list[dict]) -> dict:
    """Aggregate column 4."""
    total = sum(int(r.get("v4", 0)) for r in rows)
    return {"sum_4": total, "rows": len(rows)}

def _summarise_5(rows: list[dict]) -> dict:
    """Aggregate column 5."""
    total = sum(int(r.get("v5", 0)) for r in rows)
    return {"sum_5": total, "rows": len(rows)}

