"""
AST Static Analyzer
Analyzes Python code using the Abstract Syntax Tree (ast) module
to detect security vulnerabilities, anti-patterns, and style issues
before sending to the AI for deeper review.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ASTIssue:
    line: int
    col: int
    severity: str   # critical | warning | suggestion | good
    category: str   # security | performance | maintainability | best_practices | code_style
    title: str
    description: str
    fix: str
    rule_id: str = ""


class ASTAnalyzer:
    """
    Performs static analysis on Python source code using AST traversal.
    Checks for 12+ categories of issues without requiring code execution.
    """

    DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}

    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',  "Hardcoded password",   "SEC001"),
        (r'(?i)(api_key|apikey|secret_key)\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded API key", "SEC002"),
        (r'(?i)(token|auth_token)\s*=\s*["\'][^"\']{8,}["\']',     "Hardcoded auth token", "SEC003"),
        (r'(?i)(secret)\s*=\s*["\'][^"\']{6,}["\']',               "Hardcoded secret",     "SEC004"),
        (r'(?i)(private_key|privkey)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded private key","SEC005"),
    ]

    SQL_CONCAT_PATTERNS = [
        r'(?i)(execute|query)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP).+["\']?\s*\+',
        r'(?i)(execute|query)\s*\(\s*f["\'].*(SELECT|INSERT|UPDATE|DELETE)',
        r'(?i)["\'].*(SELECT|INSERT|UPDATE|DELETE).*["\']\s*%',
    ]

    def analyze(self, code: str, filename: str = "code.py") -> List[ASTIssue]:
        """Run all checks and return a list of discovered issues."""
        issues: List[ASTIssue] = []

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            return [ASTIssue(
                line=e.lineno or 1, col=0,
                severity="critical", category="code_style",
                title="Syntax error",
                description=f"Python cannot parse this file: {e.msg}",
                fix="Fix the syntax error before running other checks.",
                rule_id="SYN001"
            )]

        lines = code.splitlines()

        # Security checks
        issues += self._check_hardcoded_secrets(lines)
        issues += self._check_sql_injection(lines)
        issues += self._check_dangerous_functions(tree)
        issues += self._check_shell_injection(tree, lines)

        # Best practices
        issues += self._check_bare_except(tree)
        issues += self._check_mutable_defaults(tree)
        issues += self._check_global_usage(tree)
        issues += self._check_file_without_context_manager(tree, lines)
        issues += self._check_assert_in_prod(tree)

        # Performance
        issues += self._check_inefficient_loops(tree)
        issues += self._check_repeated_membership_test(tree)

        # Maintainability
        issues += self._check_missing_docstrings(tree)
        issues += self._check_long_functions(tree)
        issues += self._check_too_many_args(tree)

        # Code style
        issues += self._check_missing_type_hints(tree)
        issues += self._check_magic_numbers(tree)

        # Remove duplicates on the same line with same rule
        seen = set()
        unique = []
        for issue in issues:
            key = (issue.line, issue.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return sorted(unique, key=lambda i: ({"critical": 0, "warning": 1, "suggestion": 2}
                                              .get(i.severity, 3), i.line))

    # ─── Security ────────────────────────────────────────────────────────────

    def _check_hardcoded_secrets(self, lines: List[str]) -> List[ASTIssue]:
        issues = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, name, rule_id in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    issues.append(ASTIssue(
                        line=i, col=0,
                        severity="critical", category="security",
                        title=f"{name} detected",
                        description=(
                            f"{name} found on line {i}. Credentials in source code are "
                            "exposed to anyone with repo access and persist in git history forever."
                        ),
                        fix=(
                            "Use environment variables:\n"
                            "  import os\n"
                            "  SECRET = os.environ.get('SECRET_KEY')\n"
                            "Or use python-dotenv / a secrets manager (AWS Secrets Manager, HashiCorp Vault)."
                        ),
                        rule_id=rule_id
                    ))
        return issues

    def _check_sql_injection(self, lines: List[str]) -> List[ASTIssue]:
        issues = []
        for i, line in enumerate(lines, 1):
            for pattern in self.SQL_CONCAT_PATTERNS:
                if re.search(pattern, line):
                    issues.append(ASTIssue(
                        line=i, col=0,
                        severity="critical", category="security",
                        title="SQL injection vulnerability",
                        description=(
                            f"Line {i} constructs SQL via string formatting/concatenation. "
                            "Unsanitized user input can manipulate query logic, exposing or destroying data."
                        ),
                        fix=(
                            "Use parameterized queries:\n"
                            "  # SQLite/psycopg2\n"
                            "  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
                            "  # SQLAlchemy ORM\n"
                            "  session.query(User).filter(User.id == user_id).first()"
                        ),
                        rule_id="SEC010"
                    ))
                    break
        return issues

    def _check_dangerous_functions(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name in self.DANGEROUS_BUILTINS:
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="critical", category="security",
                        title=f"Dangerous built-in: {name}()",
                        description=(
                            f"{name}() executes arbitrary Python code. If any user-controlled input "
                            "reaches this call, it enables Remote Code Execution (RCE)."
                        ),
                        fix=(
                            f"Avoid {name}() entirely.\n"
                            "  - For data parsing: use ast.literal_eval()\n"
                            "  - For dynamic imports: use importlib.import_module()\n"
                            "  - For calculations: use a safe expression parser library."
                        ),
                        rule_id="SEC020"
                    ))
        return issues

    def _check_shell_injection(self, tree: ast.AST, lines: List[str]) -> List[ASTIssue]:
        issues = []
        shell_calls = {"os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                full_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    full_name = f"{node.func.value.id}.{node.func.attr}"
                if full_name in shell_calls:
                    # Check if shell=True is passed
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                            issues.append(ASTIssue(
                                line=node.lineno, col=node.col_offset,
                                severity="critical", category="security",
                                title=f"Shell injection risk: {full_name}(shell=True)",
                                description=(
                                    "shell=True allows shell metacharacters in input to execute arbitrary commands. "
                                    "Never use shell=True with user-supplied data."
                                ),
                                fix=(
                                    "Pass a list of arguments instead:\n"
                                    "  subprocess.run(['ls', '-la', path])  # safe\n"
                                    "  subprocess.run(f'ls {path}', shell=True)  # dangerous"
                                ),
                                rule_id="SEC030"
                            ))
        return issues

    # ─── Best Practices ──────────────────────────────────────────────────────

    def _check_bare_except(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                issues.append(ASTIssue(
                    line=node.lineno, col=node.col_offset,
                    severity="warning", category="best_practices",
                    title="Bare except clause",
                    description=(
                        "bare 'except:' catches ALL exceptions including SystemExit, "
                        "KeyboardInterrupt, and GeneratorExit. This hides real errors and "
                        "makes the program impossible to kill cleanly."
                    ),
                    fix=(
                        "Catch only the exceptions you expect:\n"
                        "  try:\n"
                        "      ...\n"
                        "  except (ValueError, TypeError) as e:\n"
                        "      logger.error(f'Expected error: {e}')"
                    ),
                    rule_id="BP001"
                ))
        return issues

    def _check_mutable_defaults(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        type_name = {ast.List: "list", ast.Dict: "dict", ast.Set: "set"}[type(default)]
                        issues.append(ASTIssue(
                            line=node.lineno, col=node.col_offset,
                            severity="warning", category="best_practices",
                            title=f"Mutable default argument ({type_name}) in '{node.name}'",
                            description=(
                                f"Default mutable {type_name} is created once and shared across all calls. "
                                "Mutating it in one call affects all future calls — a classic Python gotcha."
                            ),
                            fix=(
                                f"Use None as sentinel and initialize inside the function:\n"
                                f"  def {node.name}(items=None):\n"
                                f"      if items is None:\n"
                                f"          items = {type_name}()"
                            ),
                            rule_id="BP002"
                        ))
        return issues

    def _check_global_usage(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                issues.append(ASTIssue(
                    line=node.lineno, col=node.col_offset,
                    severity="warning", category="best_practices",
                    title=f"Global variable usage: {', '.join(node.names)}",
                    description=(
                        "Global state creates hidden coupling between functions, makes unit testing hard, "
                        "and causes race conditions in concurrent/async code."
                    ),
                    fix=(
                        "Pass state explicitly as parameters, or encapsulate in a class:\n"
                        "  class AppState:\n"
                        "      def __init__(self):\n"
                        "          self.counter = 0"
                    ),
                    rule_id="BP003"
                ))
        return issues

    def _check_file_without_context_manager(self, tree: ast.AST, lines: List[str]) -> List[ASTIssue]:
        issues = []
        with_lines: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    if hasattr(item.context_expr, "lineno"):
                        with_lines.add(item.context_expr.lineno)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    if node.lineno not in with_lines:
                        issues.append(ASTIssue(
                            line=node.lineno, col=node.col_offset,
                            severity="warning", category="best_practices",
                            title="File opened without context manager",
                            description=(
                                "open() without 'with' risks a file descriptor leak if an exception "
                                "occurs before .close() is called."
                            ),
                            fix=(
                                "Always use 'with':\n"
                                "  with open('file.txt', 'r') as f:\n"
                                "      data = f.read()"
                            ),
                            rule_id="BP004"
                        ))
        return issues

    def _check_assert_in_prod(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                issues.append(ASTIssue(
                    line=node.lineno, col=node.col_offset,
                    severity="warning", category="best_practices",
                    title="Assert used for runtime validation",
                    description=(
                        "assert statements are disabled when Python runs with -O (optimize) flag. "
                        "Never use assert for input validation or security checks in production."
                    ),
                    fix=(
                        "Use explicit checks instead:\n"
                        "  if not condition:\n"
                        "      raise ValueError('condition must be true')"
                    ),
                    rule_id="BP005"
                ))
        return issues

    # ─── Performance ─────────────────────────────────────────────────────────

    def _check_inefficient_loops(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.For):
                # Detect: for i in range(len(lst)) — should use enumerate
                if (isinstance(node.iter, ast.Call)
                        and isinstance(node.iter.func, ast.Name)
                        and node.iter.func.id == "range"
                        and len(node.iter.args) == 1
                        and isinstance(node.iter.args[0], ast.Call)
                        and isinstance(node.iter.args[0].func, ast.Name)
                        and node.iter.args[0].func.id == "len"):
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="suggestion", category="performance",
                        title="Use enumerate() instead of range(len(...))",
                        description=(
                            "range(len(lst)) is unpythonic and slightly slower. "
                            "enumerate() is idiomatic and gives both index and value."
                        ),
                        fix=(
                            "  # Before\n"
                            "  for i in range(len(items)):\n"
                            "      print(i, items[i])\n\n"
                            "  # After\n"
                            "  for i, item in enumerate(items):\n"
                            "      print(i, item)"
                        ),
                        rule_id="PERF001"
                    ))
        return issues

    def _check_repeated_membership_test(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for child in ast.walk(node):
                    if isinstance(child, ast.For):
                        for subnode in ast.walk(child):
                            if (isinstance(subnode, ast.Compare)
                                    and any(isinstance(op, (ast.In, ast.NotIn)) for op in subnode.ops)):
                                for comparator in subnode.comparators:
                                    if isinstance(comparator, ast.List):
                                        issues.append(ASTIssue(
                                            line=subnode.lineno, col=subnode.col_offset,
                                            severity="suggestion", category="performance",
                                            title="Use set for O(1) membership test",
                                            description=(
                                                "Membership test against a list inside a loop is O(n) per check. "
                                                "Converting to a set gives O(1) lookups."
                                            ),
                                            fix=(
                                                "  allowed = {'admin', 'user', 'mod'}  # O(1)\n"
                                                "  if role in allowed:  # fast\n"
                                                "      ..."
                                            ),
                                            rule_id="PERF002"
                                        ))
                                        break
        return issues

    # ─── Maintainability ─────────────────────────────────────────────────────

    def _check_missing_docstrings(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.startswith("_"):
                    continue
                # Skip trivial one-line/two-line functions — docstrings add little value there
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and len(node.body) <= 1:
                    continue
                has_doc = (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                )
                if not has_doc:
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="suggestion", category="maintainability",
                        title=f"Missing docstring in public {kind} '{node.name}'",
                        description=(
                            f"Public {kind} '{node.name}' has no docstring. "
                            "Docstrings are essential for auto-generated documentation and are "
                            "required by Google Python Style Guide."
                        ),
                        fix=(
                            f'def {node.name}(param: str) -> None:\n'
                            '    """Brief one-line summary.\n\n'
                            '    Args:\n'
                            '        param: Description of param.\n\n'
                            '    Returns:\n'
                            '        Description of return value.\n\n'
                            '    Raises:\n'
                            '        ValueError: If param is invalid.\n'
                            '    """'
                        ),
                        rule_id="MAINT001"
                    ))
        return issues

    def _check_long_functions(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node_lines = [n.lineno for n in ast.walk(node) if hasattr(n, "lineno")]
                if not node_lines:
                    continue
                length = max(node_lines) - node.lineno
                if length > 50:
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="warning", category="maintainability",
                        title=f"Function '{node.name}' is too long ({length} lines)",
                        description=(
                            f"Functions over 50 lines are hard to test, review, and reason about. "
                            f"'{node.name}' spans ~{length} lines. Google style guide recommends ≤40 lines."
                        ),
                        fix=(
                            "Apply the Single Responsibility Principle:\n"
                            "  - Extract logical blocks into helper functions\n"
                            "  - Aim for functions that do exactly one thing\n"
                            "  - Good target: ≤30 lines per function"
                        ),
                        rule_id="MAINT002"
                    ))
        return issues

    def _check_too_many_args(self, tree: ast.AST) -> List[ASTIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                all_args = node.args.args + node.args.posonlyargs + node.args.kwonlyargs
                # exclude 'self'/'cls'
                real_args = [a for a in all_args if a.arg not in ("self", "cls")]
                if len(real_args) > 5:
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="suggestion", category="maintainability",
                        title=f"Too many arguments in '{node.name}' ({len(real_args)} params)",
                        description=(
                            f"'{node.name}' takes {len(real_args)} parameters. "
                            "Functions with >5 arguments are hard to call correctly and test. "
                            "This often signals the function is doing too much."
                        ),
                        fix=(
                            "Group related parameters into a dataclass or TypedDict:\n"
                            "  from dataclasses import dataclass\n\n"
                            "  @dataclass\n"
                            "  class ReviewConfig:\n"
                            "      language: str\n"
                            "      max_issues: int\n"
                            "      include_style: bool = True\n\n"
                            "  def review(config: ReviewConfig) -> ReviewResult: ..."
                        ),
                        rule_id="MAINT003"
                    ))
        return issues

    # ─── Code Style ──────────────────────────────────────────────────────────

    def _check_missing_type_hints(self, tree: ast.AST) -> List[ASTIssue]:
        """Only flags functions with ZERO type hints anywhere — a function that's
        mostly typed with one missed parameter isn't worth flagging; that's noise."""
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                real_args = [a for a in node.args.args if a.arg not in ("self", "cls")]
                if not real_args and node.returns is not None:
                    continue
                any_annotated = any(a.annotation is not None for a in real_args) or node.returns is not None
                if real_args and not any_annotated:
                    issues.append(ASTIssue(
                        line=node.lineno, col=node.col_offset,
                        severity="suggestion", category="code_style",
                        title=f"No type hints in '{node.name}'",
                        description=(
                            f"'{node.name}' has no type annotations at all. "
                            "Type hints enable static analysis (mypy/pyright), improve IDE support, "
                            "and are expected at most companies for public functions."
                        ),
                        fix=(
                            "  from typing import Optional, List\n\n"
                            f"  def {node.name}(user_id: int, active: bool = True) -> Optional[str]:\n"
                            "      ..."
                        ),
                        rule_id="STYLE001"
                    ))
        return issues

    def _check_magic_numbers(self, tree: ast.AST) -> List[ASTIssue]:
        """Only flags numbers used as comparison thresholds (the classic 'magic number'
        smell), not every numeric literal — flagging array indices, loop bounds, etc.
        produces noise that doesn't reflect real code quality."""
        issues = []
        seen_lines: set = set()
        ALLOWED = {0, 1, -1, 2, 10, 100, 1000}
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for comparator in node.comparators + [node.left]:
                    if (isinstance(comparator, ast.Constant)
                            and isinstance(comparator.value, (int, float))
                            and comparator.value not in ALLOWED
                            and comparator.lineno not in seen_lines):
                        seen_lines.add(comparator.lineno)
                        issues.append(ASTIssue(
                            line=comparator.lineno, col=comparator.col_offset,
                            severity="suggestion", category="code_style",
                            title=f"Magic number in comparison: {comparator.value}",
                            description=(
                                f"The threshold {comparator.value} has no contextual meaning at the call site. "
                                "Magic numbers in comparisons make the intent and tuning unclear."
                            ),
                            fix=(
                                "Define a named constant:\n"
                                f"  MAX_RETRIES = {comparator.value}\n"
                                f"  if attempts > MAX_RETRIES: ..."
                            ),
                            rule_id="STYLE002"
                        ))
        return issues

    def summarize(self, issues: List[ASTIssue]) -> dict:
        """Return a summary dict for embedding in AI prompts."""
        counts = {"critical": 0, "warning": 0, "suggestion": 0}
        for i in issues:
            counts[i.severity] = counts.get(i.severity, 0) + 1
        return {
            "total": len(issues),
            "counts": counts,
            "issues": [
                {
                    "line": i.line,
                    "severity": i.severity,
                    "category": i.category,
                    "title": i.title,
                    "rule_id": i.rule_id,
                }
                for i in issues
            ]
        }
