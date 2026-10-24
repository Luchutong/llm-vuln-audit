"""Pure in-memory base64 facade; the standard module also contains CLI file IO."""
from __future__ import annotations

import ast
import base64
from types import ModuleType

from .actions import ActionIssue

ENCODING_FUNCTIONS = frozenset({
    'b64encode', 'b64decode', 'standard_b64encode', 'standard_b64decode',
    'urlsafe_b64encode', 'urlsafe_b64decode', 'b32encode', 'b32decode',
    'b32hexencode', 'b32hexdecode', 'b16encode', 'b16decode',
    'a85encode', 'a85decode', 'b85encode', 'b85decode', 'z85encode', 'z85decode',
    'encodebytes', 'decodebytes',
})
FACADE_NAME = '_audit_memory_base64'


def encoding_facade() -> ModuleType:
    facade = ModuleType('base64', 'Pure in-memory encoding functions only.')
    for name in ENCODING_FUNCTIONS:
        if hasattr(base64, name):
            setattr(facade, name, getattr(base64, name))
    return facade


def bind_encoding_imports(code: str) -> str:
    """Route explicit imports to the facade, preserving every script string value."""
    tree = ast.parse(code)
    changed = False

    class Bind(ast.NodeTransformer):
        def visit_Import(self, node):
            nonlocal changed
            result = []
            for alias in node.names:
                if alias.name == 'base64':
                    changed = True
                    result.append(ast.Assign(targets=[ast.Name(id=alias.asname or alias.name, ctx=ast.Store())],
                                             value=ast.Name(id=FACADE_NAME, ctx=ast.Load())))
                else:
                    result.append(ast.Import(names=[alias]))
            return [ast.copy_location(item, node) for item in result]

        def visit_ImportFrom(self, node):
            nonlocal changed
            if node.module != 'base64':
                return node
            changed = True
            result = []
            for alias in node.names:
                if alias.name not in ENCODING_FUNCTIONS or not hasattr(base64, alias.name):
                    raise ActionIssue('unauthorized_import', f'base64 仅开放纯内存编码 API；{alias.name} 不可用，main/encode/decode 文件入口禁止。')
                result.append(ast.copy_location(ast.Assign(
                    targets=[ast.Name(id=alias.asname or alias.name, ctx=ast.Store())],
                    value=ast.Attribute(value=ast.Name(id=FACADE_NAME, ctx=ast.Load()), attr=alias.name, ctx=ast.Load()),
                ), node))
            return result

    tree = Bind().visit(tree)
    return ast.unparse(ast.fix_missing_locations(tree)) if changed else code
