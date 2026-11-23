"""Regression tests for receiver-aware CG-013 call resolution."""
from pathlib import Path

from concurrency_guard.lsp import DocumentStore
from concurrency_guard.scanner.ast_rules import scan_file, scan_source_code


def deadlocks(source: str) -> list[str]:
    return [f.message for f in scan_source_code(source) if f.rule_id == "CG-013"]


def test_document_store_dictionary_calls_are_safe() -> None:
    import inspect

    filename = inspect.getsourcefile(DocumentStore)
    assert filename is not None
    assert not [f for f in scan_file(Path(filename)) if f.rule_id == "CG-013"]
    store = DocumentStore()
    store.open("file:///test.py", "before")
    store.update("file:///test.py", "after", version=2)
    doc = store.get("file:///test.py")
    assert doc is not None and (doc.content, doc.version) == ("after", 2)


def test_real_method_call_still_reports_once() -> None:
    source = """
import threading
class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.values = {}
    def parent(self):
        with self.lock:
            self.child()
            self.values.get("key")
    def child(self):
        with self.lock:
            return self.values.get("key")
"""
    messages = deadlocks(source)
    assert len(messages) == 1
    assert "'Store.child'" in messages[0]


def test_unrelated_classes_do_not_share_methods_or_reentrant_locks() -> None:
    source = """
import threading
class Safe:
    def __init__(self):
        self.lock = threading.RLock()
    def child(self):
        with self.lock:
            pass
class Unsafe:
    def __init__(self):
        self.lock = threading.Lock()
    def parent(self):
        with self.lock:
            self.child()
    def child(self):
        with self.lock:
            pass
class Other:
    def __init__(self):
        self.lock = threading.Lock()
    def parent(self):
        with self.lock:
            self.values.get("key")
"""
    messages = deadlocks(source)
    assert len(messages) == 1
    assert "'Unsafe.parent'" in messages[0]


def test_module_function_and_shadowed_callable() -> None:
    source = """
import threading
lock = threading.Lock()
def child():
    with lock:
        pass
def parent():
    with lock:
        child()
def shadowed(child):
    with lock:
        child()
"""
    messages = deadlocks(source)
    assert len(messages) == 1
    assert "'parent'" in messages[0]


def test_file_cache_is_not_a_redis_client() -> None:
    source = """
def cache_file(cache_manager, file_path, findings):
    cached = cache_manager.get(file_path)
    if cached is None:
        cache_manager.set(file_path, findings)
"""
    assert not scan_source_code(source)
    redis = source.replace("cache_manager", "redis")
    assert any(f.rule_id == "CG-027" for f in scan_source_code(redis))
    unrelated = redis.replace("redis.set(file_path", "other_redis.set(file_path")
    assert not any(f.rule_id == "CG-027" for f in scan_source_code(unrelated))
    other_key = redis.replace("redis.set(file_path", "redis.set(other_path")
    assert not any(f.rule_id == "CG-027" for f in scan_source_code(other_key))
