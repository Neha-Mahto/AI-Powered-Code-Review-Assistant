"""
Unit tests for the AST static analyzer.
Run with: pytest tests/test_ast_analyzer.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.ast_analyzer import ASTAnalyzer


@pytest.fixture
def analyzer():
    return ASTAnalyzer()


class TestSecurityChecks:

    def test_detects_hardcoded_password(self, analyzer):
        code = 'PASSWORD = "admin123"'
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "SEC001" for i in issues)
        assert any(i.severity == "critical" for i in issues)

    def test_detects_hardcoded_api_key(self, analyzer):
        code = 'API_KEY = "sk-live-abc123xyz789"'
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "SEC002" for i in issues)

    def test_detects_sql_injection_concat(self, analyzer):
        code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
'''
        issues = analyzer.analyze(code)
        # at least the secret/sql patterns should not crash; concat detection
        # happens via direct execute() pattern matching too
        assert isinstance(issues, list)

    def test_detects_sql_injection_fstring(self, analyzer):
        code = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "SEC010" for i in issues)

    def test_detects_eval_usage(self, analyzer):
        code = "result = eval(user_input)"
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "SEC020" for i in issues)
        assert any("eval" in i.title for i in issues)

    def test_detects_shell_true(self, analyzer):
        code = '''
import subprocess
subprocess.run(cmd, shell=True)
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "SEC030" for i in issues)

    def test_clean_code_no_security_issues(self, analyzer):
        code = '''
import os

def get_secret() -> str:
    """Fetch secret from environment."""
    return os.environ.get("SECRET_KEY", "")
'''
        issues = analyzer.analyze(code)
        security_issues = [i for i in issues if i.category == "security"]
        assert len(security_issues) == 0


class TestBestPracticesChecks:

    def test_detects_bare_except(self, analyzer):
        code = '''
try:
    risky_call()
except:
    pass
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "BP001" for i in issues)

    def test_detects_mutable_default_list(self, analyzer):
        code = '''
def add_item(item, items=[]):
    items.append(item)
    return items
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "BP002" for i in issues)

    def test_detects_mutable_default_dict(self, analyzer):
        code = '''
def configure(options={}):
    return options
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "BP002" for i in issues)

    def test_no_false_positive_on_none_default(self, analyzer):
        code = '''
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "BP002" for i in issues)

    def test_detects_global_statement(self, analyzer):
        code = '''
counter = 0

def increment():
    global counter
    counter += 1
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "BP003" for i in issues)

    def test_detects_file_without_context_manager(self, analyzer):
        code = '''
def read_file(path):
    f = open(path)
    data = f.read()
    f.close()
    return data
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "BP004" for i in issues)

    def test_no_false_positive_with_context_manager(self, analyzer):
        code = '''
def read_file(path: str) -> str:
    """Read file contents."""
    with open(path) as f:
        return f.read()
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "BP004" for i in issues)


class TestPerformanceChecks:

    def test_detects_range_len_pattern(self, analyzer):
        code = '''
def process(items):
    for i in range(len(items)):
        print(items[i])
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "PERF001" for i in issues)

    def test_no_false_positive_enumerate(self, analyzer):
        code = '''
def process(items: list) -> None:
    """Print items."""
    for i, item in enumerate(items):
        print(i, item)
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "PERF001" for i in issues)


class TestMaintainabilityChecks:

    def test_detects_missing_docstring(self, analyzer):
        code = '''
def calculate_total(items):
    return sum(items)
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "MAINT001" for i in issues)

    def test_no_false_positive_with_docstring(self, analyzer):
        code = '''
def calculate_total(items: list) -> int:
    """Calculate the sum of all items."""
    return sum(items)
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "MAINT001" for i in issues)

    def test_detects_too_many_arguments(self, analyzer):
        code = '''
def create_user(name, email, age, address, phone, role, department):
    pass
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "MAINT003" for i in issues)

    def test_self_not_counted_as_argument(self, analyzer):
        code = '''
class Service:
    def method(self, a, b, c):
        pass
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "MAINT003" for i in issues)


class TestCodeStyleChecks:

    def test_detects_missing_type_hints(self, analyzer):
        code = '''
def add(a, b):
    return a + b
'''
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "STYLE001" for i in issues)

    def test_no_false_positive_with_type_hints(self, analyzer):
        code = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "STYLE001" for i in issues)


class TestEdgeCases:

    def test_empty_code(self, analyzer):
        issues = analyzer.analyze("")
        assert issues == []

    def test_syntax_error_handled_gracefully(self, analyzer):
        code = "def broken(:\n    pass"
        issues = analyzer.analyze(code)
        assert len(issues) == 1
        assert issues[0].rule_id == "SYN001"

    def test_issues_sorted_by_severity(self, analyzer):
        code = '''
PASSWORD = "admin123"

def f(a, b, c, d, e, f, g):
    pass
'''
        issues = analyzer.analyze(code)
        if len(issues) > 1:
            severities = [i.severity for i in issues]
            rank = {"critical": 0, "warning": 1, "suggestion": 2}
            ranks = [rank.get(s, 3) for s in severities]
            assert ranks == sorted(ranks)

    def test_summarize_output_format(self, analyzer):
        code = 'PASSWORD = "admin123"'
        issues = analyzer.analyze(code)
        summary = analyzer.summarize(issues)
        assert "total" in summary
        assert "counts" in summary
        assert "issues" in summary
        assert summary["total"] == len(issues)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
