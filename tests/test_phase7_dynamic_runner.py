"""Unit tests for Phase 7: dynamic route discovery, payload synthesis, and barrier verification."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from concurrency_guard.runner.barrier_engine import run_dynamic_barrier_verification
from concurrency_guard.runner.route_inspector import discover_fastapi_targets
from concurrency_guard.runner.schema_synthesizer import synthesize_request_payload


def _load_module(file_path: Path, module_name: str) -> ModuleType:
    """Load a Python file as a module, registering it in sys.modules."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


INVENTORY_PATH = Path("examples/vulnerable_inventory.py")


def test_discovers_arbitrary_inventory_routes() -> None:
    """Verify discover_fastapi_targets finds /inventory/reserve, extracts ReserveStockRequest,
    and identifies stock_quantity as the mutated attribute."""
    module = _load_module(INVENTORY_PATH, "test_inv_discovery")
    source_code = INVENTORY_PATH.read_text(encoding="utf-8")

    targets = discover_fastapi_targets(module, source_code)

    # Should discover both /inventory/reserve and /inventory/reserve-safe
    paths = {t.path for t in targets}
    assert "/inventory/reserve" in paths

    # Find the vulnerable route
    vuln = next(t for t in targets if t.path == "/inventory/reserve")
    assert vuln.function_name == "reserve_stock"
    assert vuln.method == "POST"

    # Pydantic model must be extracted
    assert vuln.pydantic_model is not None
    assert vuln.pydantic_model.__name__ == "ReserveStockRequest"

    # Mutated attribute must be stock_quantity
    assert vuln.mutated_attribute == "stock_quantity"

    # Vulnerable route must NOT have with_for_update
    assert vuln.uses_for_update is False

    # Safe route MUST have with_for_update
    safe = next(t for t in targets if t.path == "/inventory/reserve-safe")
    assert safe.uses_for_update is True


def test_synthesizes_pydantic_payload_automatically() -> None:
    """Verify synthesize_request_payload(ReserveStockRequest, 50) -> {"item_id":1, "quantity":50}
    with zero manual configuration."""
    module = _load_module(INVENTORY_PATH, "test_inv_synthesis")
    ReserveStockRequest = module.ReserveStockRequest

    payload = synthesize_request_payload(ReserveStockRequest, initial_quota=50)

    assert payload["item_id"] == 1
    assert payload["quantity"] == 50
    assert len(payload) == 2


@pytest.mark.asyncio
async def test_dynamic_barrier_proves_inventory_oversell() -> None:
    """Run dynamic barrier on reserve_stock and prove stock_quantity drops to -950
    (invariant_violated == True)."""
    results = await run_dynamic_barrier_verification(
        file_path=INVENTORY_PATH,
        function_name="reserve_stock",
        workers=20,
        initial_quota=50,
    )

    assert len(results) == 1
    result = results[0]

    assert result["endpoint_path"] == "/inventory/reserve"
    assert result["function_name"] == "reserve_stock"
    assert result["mutated_field"] == "stock_quantity"
    assert result["workers"] == 20
    assert result["initial_balance"] == 50
    assert result["success_count"] > 1
    assert result["final_balance"] < 0
    assert result["invariant_violated"] is True
    # Synthesized payload must be present
    assert result["synthesized_payload"]["item_id"] == 1
    assert result["synthesized_payload"]["quantity"] == 50


@pytest.mark.asyncio
async def test_dynamic_barrier_passes_safe_inventory_route() -> None:
    """Run dynamic barrier on reserve_stock_safe and prove stock_quantity == 0
    and success_count == 1 (invariant_violated == False)."""
    results = await run_dynamic_barrier_verification(
        file_path=INVENTORY_PATH,
        function_name="reserve_stock_safe",
        workers=20,
        initial_quota=50,
    )

    assert len(results) == 1
    result = results[0]

    assert result["endpoint_path"] == "/inventory/reserve-safe"
    assert result["function_name"] == "reserve_stock_safe"
    assert result["mutated_field"] == "stock_quantity"
    assert result["workers"] == 20
    assert result["success_count"] == 1
    assert result["final_balance"] == 0
    assert result["invariant_violated"] is False
