#!/usr/bin/env python3
"""
CodeGraphContext Demo - Local Code Graph Analyzer
Hacktoberfest 2025 - Complete Code Analysis Program

A Python program that analyzes local codebases and builds a graph database
of code relationships, similar to CodeGraphContext. This single-file program
demonstrates code indexing, relationship analysis, and graph querying.

Features:
- Parse Python files and extract classes, functions, imports, and calls
- Build a graph database of code relationships
- Query for callers, callees, dependencies, and hierarchies
- Find dead code and complexity analysis
- Save/load graph to JSON (simulating database persistence)
- Interactive CLI for exploring code relationships
"""

import os
import re
import json
import ast
import sys
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import inspect


@dataclass
class CodeNode:
    """Represents a node in the code graph (function, class, etc.)."""
    name: str
    type: str  # 'function', 'class', 'method', 'module'
    file_path: str
    line_number: int
    complexity: int = 0
    docstring: Optional[str] = None
    parameters: List[str] = None
    parent_class: Optional[str] = None

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []


@dataclass
class CodeRelationship:
    """Represents a relationship between code nodes."""
    source: str
    target: str
    type: str  # 'calls', 'inherits', 'imports', 'contains', 'uses'
    file_path: str
    line_number: int


class CodeGraphAnalyzer:
    """Analyzes Python code and builds a graph of relationships."""

    def __init__(self):
        self.nodes: Dict[str, CodeNode] = {}
        self.relationships: List[CodeRelationship] = []
        self.file_index: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_index: Dict[str, Set[str]] = defaultdict(set)

    def analyze_file(self, file_path: str) -> None:
        """Analyze a single Python file and add to graph."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse the AST
            tree = ast.parse(content, filename=file_path)

            # Extract nodes and relationships
            self._extract_nodes_from_ast(tree, file_path, content)
            self._extract_relationships_from_ast(tree, file_path, content)

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

    def analyze_directory(self, directory_path: str, exclude_patterns: List[str] = None) -> None:
        """Analyze all Python files in a directory."""
        exclude_patterns = exclude_patterns or ['__pycache__', '.git', 'venv', 'env', 'node_modules']

        for root, dirs, files in os.walk(directory_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]

            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    print(f"Analyzing {file_path}")
                    self.analyze_file(file_path)

    def _extract_nodes_from_ast(self, tree: ast.AST, file_path: str, content: str) -> None:
        """Extract function and class definitions from AST."""
        lines = content.split('\n')

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Function or method
                node_type = 'method' if self._is_method(node) else 'function'
                parent_class = self._get_parent_class(node)

                code_node = CodeNode(
                    name=node.name,
                    type=node_type,
                    file_path=file_path,
                    line_number=node.lineno,
                    complexity=self._calculate_complexity(node),
                    docstring=ast.get_docstring(node),
                    parameters=[arg.arg for arg in node.args.args],
                    parent_class=parent_class
                )

                full_name = f"{parent_class}.{node.name}" if parent_class else node.name
                self.nodes[full_name] = code_node
                self.file_index[file_path].add(full_name)

            elif isinstance(node, ast.ClassDef):
                # Class
                code_node = CodeNode(
                    name=node.name,
                    type='class',
                    file_path=file_path,
                    line_number=node.lineno,
                    docstring=ast.get_docstring(node)
                )

                self.nodes[node.name] = code_node
                self.file_index[file_path].add(node.name)

    def _extract_relationships_from_ast(self, tree: ast.AST, file_path: str, content: str) -> None:
        """Extract relationships from AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Function calls
                if isinstance(node.func, ast.Name):
                    caller = self._get_current_function(node)
                    if caller and node.func.id in self.nodes:
                        self.relationships.append(CodeRelationship(
                            source=caller,
                            target=node.func.id,
                            type='calls',
                            file_path=file_path,
                            line_number=node.lineno
                        ))
                        self.reverse_index[node.func.id].add(caller)

            elif isinstance(node, ast.ClassDef):
                # Inheritance
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id in self.nodes:
                        self.relationships.append(CodeRelationship(
                            source=node.name,
                            target=base.id,
                            type='inherits',
                            file_path=file_path,
                            line_number=node.lineno
                        ))

            elif isinstance(node, ast.Import):
                # Import statements
                for alias in node.names:
                    module_name = alias.name
                    self.relationships.append(CodeRelationship(
                        source=os.path.basename(file_path)[:-3],  # module name
                        target=module_name,
                        type='imports',
                        file_path=file_path,
                        line_number=node.lineno
                    ))

            elif isinstance(node, ast.ImportFrom):
                # From imports
                module_name = node.module or ''
                for alias in node.names:
                    full_name = f"{module_name}.{alias.name}"
                    self.relationships.append(CodeRelationship(
                        source=os.path.basename(file_path)[:-3],
                        target=full_name,
                        type='imports',
                        file_path=file_path,
                        line_number=node.lineno
                    ))

    def _is_method(self, node: ast.FunctionDef) -> bool:
        """Check if a function is a method (inside a class)."""
        for parent in ast.iterancestors(node):
            if isinstance(parent, ast.ClassDef):
                return True
        return False

    def _get_parent_class(self, node: ast.FunctionDef) -> Optional[str]:
        """Get the parent class name for a method."""
        for parent in ast.iterancestors(node):
            if isinstance(parent, ast.ClassDef):
                return parent.name
        return None

    def _get_current_function(self, node: ast.AST) -> Optional[str]:
        """Get the name of the current function/method context."""
        for parent in ast.iterancestors(node):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent_class = self._get_parent_class(parent)
                return f"{parent_class}.{parent.name}" if parent_class else parent.name
        return None

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With,
                               ast.Try, ast.ExceptHandler, ast.Assert)):
                complexity += 1
            elif isinstance(child, ast.BoolOp) and len(child.values) > 1:
                complexity += len(child.values) - 1

        return complexity

    def find_callers(self, function_name: str) -> List[str]:
        """Find all functions that call the given function."""
        return list(self.reverse_index.get(function_name, set()))

    def find_callees(self, function_name: str) -> List[str]:
        """Find all functions called by the given function."""
        callees = []
        for rel in self.relationships:
            if rel.source == function_name and rel.type == 'calls':
                callees.append(rel.target)
        return callees

    def get_class_hierarchy(self, class_name: str) -> List[str]:
        """Get the inheritance hierarchy for a class."""
        hierarchy = []
        current = class_name

        while current:
            hierarchy.append(current)
            # Find parent class
            parent = None
            for rel in self.relationships:
                if rel.source == current and rel.type == 'inherits':
                    parent = rel.target
                    break
            current = parent

        return hierarchy

    def find_dead_code(self) -> List[str]:
        """Find potentially dead code (functions/methods that are never called)."""
        called_functions = set()
        all_functions = set()

        # Collect all functions
        for node in self.nodes.values():
            if node.type in ['function', 'method']:
                all_functions.add(node.name)

        # Collect called functions
        for rel in self.relationships:
            if rel.type == 'calls':
                called_functions.add(rel.target)

        # Functions that are defined but never called
        return list(all_functions - called_functions)

    def get_most_complex_functions(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get the most complex functions by cyclomatic complexity."""
        complexities = []
        for name, node in self.nodes.items():
            if node.type in ['function', 'method'] and node.complexity > 0:
                complexities.append((name, node.complexity))

        complexities.sort(key=lambda x: x[1], reverse=True)
        return complexities[:limit]

    def search_code(self, query: str) -> List[str]:
        """Search for code elements containing the query."""
        results = []
        query_lower = query.lower()

        for name, node in self.nodes.items():
            if (query_lower in name.lower() or
                (node.docstring and query_lower in node.docstring.lower())):
                results.append(name)

        return results

    def get_dependencies(self, module_name: str) -> List[str]:
        """Get all modules imported by a given module."""
        dependencies = []
        for rel in self.relationships:
            if rel.source == module_name and rel.type == 'imports':
                dependencies.append(rel.target)
        return dependencies

    def save_graph(self, filename: str) -> None:
        """Save the code graph to a JSON file."""
        data = {
            'nodes': {name: asdict(node) for name, node in self.nodes.items()},
            'relationships': [asdict(rel) for rel in self.relationships],
            'file_index': {k: list(v) for k, v in self.file_index.items()},
            'reverse_index': {k: list(v) for k, v in self.reverse_index.items()}
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    def load_graph(self, filename: str) -> None:
        """Load the code graph from a JSON file."""
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.nodes = {name: CodeNode(**node_data) for name, node_data in data['nodes'].items()}
        self.relationships = [CodeRelationship(**rel_data) for rel_data in data['relationships']]
        self.file_index = {k: set(v) for k, v in data['file_index'].items()}
        self.reverse_index = {k: set(v) for k, v in data['reverse_index'].items()}


class CodeGraphCLI:
    """Command-line interface for the Code Graph Analyzer."""

    def __init__(self):
        self.analyzer = CodeGraphAnalyzer()

    def run(self):
        """Run the interactive CLI."""
        print("🔍 CodeGraphContext Demo - Local Code Analyzer")
        print("=" * 55)
        print("Analyze your codebase and explore relationships!")
        print("Type 'help' for commands, 'quit' to exit.")
        print("-" * 55)

        while True:
            try:
                command = input("\n> ").strip()

                if not command:
                    continue

                if command.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break

                self.process_command(command)

            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def process_command(self, command: str):
        """Process a user command."""
        parts = command.split()
        cmd = parts[0].lower()

        if cmd == 'help':
            self.show_help()

        elif cmd == 'analyze' and len(parts) > 1:
            path = ' '.join(parts[1:])
            if os.path.isfile(path):
                print(f"Analyzing file: {path}")
                self.analyzer.analyze_file(path)
                print(f"✅ Analysis complete. Found {len(self.analyzer.nodes)} code elements.")
            elif os.path.isdir(path):
                print(f"Analyzing directory: {path}")
                self.analyzer.analyze_directory(path)
                print(f"✅ Analysis complete. Found {len(self.analyzer.nodes)} code elements.")
            else:
                print(f"❌ Path not found: {path}")

        elif cmd == 'callers' and len(parts) > 1:
            func_name = ' '.join(parts[1:])
            callers = self.analyzer.find_callers(func_name)
            if callers:
                print(f"Functions calling '{func_name}':")
                for caller in callers:
                    print(f"  • {caller}")
            else:
                print(f"No callers found for '{func_name}'")

        elif cmd == 'callees' and len(parts) > 1:
            func_name = ' '.join(parts[1:])
            callees = self.analyzer.find_callees(func_name)
            if callees:
                print(f"Functions called by '{func_name}':")
                for callee in callees:
                    print(f"  • {callee}")
            else:
                print(f"No callees found for '{func_name}'")

        elif cmd == 'hierarchy' and len(parts) > 1:
            class_name = ' '.join(parts[1:])
            hierarchy = self.analyzer.get_class_hierarchy(class_name)
            if hierarchy:
                print(f"Inheritance hierarchy for '{class_name}':")
                for i, cls in enumerate(hierarchy):
                    indent = "  " * i
                    print(f"{indent}• {cls}")
            else:
                print(f"No hierarchy found for '{class_name}'")

        elif cmd == 'dead':
            dead_code = self.analyzer.find_dead_code()
            if dead_code:
                print("Potentially dead code (never called):")
                for code in dead_code:
                    print(f"  • {code}")
            else:
                print("No dead code found!")

        elif cmd == 'complex':
            limit = int(parts[1]) if len(parts) > 1 else 5
            complex_funcs = self.analyzer.get_most_complex_functions(limit)
            if complex_funcs:
                print(f"Most complex functions (top {limit}):")
                for name, complexity in complex_funcs:
                    print(f"  • {name}: complexity {complexity}")
            else:
                print("No complexity data available.")

        elif cmd == 'search' and len(parts) > 1:
            query = ' '.join(parts[1:])
            results = self.analyzer.search_code(query)
            if results:
                print(f"Search results for '{query}':")
                for result in results:
                    print(f"  • {result}")
            else:
                print(f"No results found for '{query}'")

        elif cmd == 'deps' and len(parts) > 1:
            module = ' '.join(parts[1:])
            deps = self.analyzer.get_dependencies(module)
            if deps:
                print(f"Dependencies of '{module}':")
                for dep in deps:
                    print(f"  • {dep}")
            else:
                print(f"No dependencies found for '{module}'")

        elif cmd == 'save' and len(parts) > 1:
            filename = parts[1]
            self.analyzer.save_graph(filename)
            print(f"✅ Graph saved to {filename}")

        elif cmd == 'load' and len(parts) > 1:
            filename = parts[1]
            if os.path.exists(filename):
                self.analyzer.load_graph(filename)
                print(f"✅ Graph loaded from {filename}")
            else:
                print(f"❌ File not found: {filename}")

        elif cmd == 'stats':
            print("Code Graph Statistics:")
            print(f"  • Total nodes: {len(self.analyzer.nodes)}")
            print(f"  • Total relationships: {len(self.analyzer.relationships)}")
            print(f"  • Files indexed: {len(self.analyzer.file_index)}")

            type_counts = defaultdict(int)
            for node in self.analyzer.nodes.values():
                type_counts[node.type] += 1

            print("  • Node types:")
            for node_type, count in type_counts.items():
                print(f"    - {node_type}: {count}")

        else:
            print("❌ Unknown command. Type 'help' for available commands.")

    def show_help(self):
        """Show help information."""
        print("\n📋 Available Commands:")
        print("  analyze <path>    - Analyze a file or directory")
        print("  callers <func>    - Find functions that call the given function")
        print("  callees <func>    - Find functions called by the given function")
        print("  hierarchy <class> - Show class inheritance hierarchy")
        print("  dead              - Find potentially dead code")
        print("  complex [n]       - Show most complex functions (default top 5)")
        print("  search <query>    - Search for code elements")
        print("  deps <module>     - Show module dependencies")
        print("  save <file>       - Save graph to JSON file")
        print("  load <file>       - Load graph from JSON file")
        print("  stats             - Show graph statistics")
        print("  help              - Show this help")
        print("  quit              - Exit the program")


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        # Command-line mode
        analyzer = CodeGraphAnalyzer()

        if sys.argv[1] == 'analyze' and len(sys.argv) > 2:
            path = sys.argv[2]
            if os.path.isfile(path):
                analyzer.analyze_file(path)
            elif os.path.isdir(path):
                analyzer.analyze_directory(path)
            else:
                print(f"Path not found: {path}")
                return

            print(f"Analysis complete. Found {len(analyzer.nodes)} code elements.")

            if len(sys.argv) > 3 and sys.argv[3] == '--save':
                output_file = sys.argv[4] if len(sys.argv) > 4 else 'code_graph.json'
                analyzer.save_graph(output_file)
                print(f"Graph saved to {output_file}")

        elif sys.argv[1] == 'query' and len(sys.argv) > 3:
            graph_file = sys.argv[2]
            query_type = sys.argv[3]
            target = sys.argv[4] if len(sys.argv) > 4 else ''

            if os.path.exists(graph_file):
                analyzer.load_graph(graph_file)

                if query_type == 'callers':
                    results = analyzer.find_callers(target)
                elif query_type == 'callees':
                    results = analyzer.find_callees(target)
                elif query_type == 'hierarchy':
                    results = analyzer.get_class_hierarchy(target)
                elif query_type == 'dead':
                    results = analyzer.find_dead_code()
                else:
                    print(f"Unknown query type: {query_type}")
                    return

                print(f"Results for {query_type} of '{target}':")
                for result in results:
                    print(f"  • {result}")
            else:
                print(f"Graph file not found: {graph_file}")

        else:
            print("Usage:")
            print("  python code_graph_analyzer.py analyze <path> [--save <output.json>]")
            print("  python code_graph_analyzer.py query <graph.json> <callers|callees|hierarchy|dead> [target]")
    else:
        # Interactive mode
        cli = CodeGraphCLI()
        cli.run()


if __name__ == "__main__":
    main()
