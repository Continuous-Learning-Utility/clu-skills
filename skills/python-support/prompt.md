# Python Development Context

## Code Style
- Follow PEP 8: 4-space indentation, 88-char lines (Black default)
- Use type annotations on all public functions and methods
- Prefer `dataclasses` or `pydantic` models over raw dicts for structured data
- Use `pathlib.Path` instead of `os.path` for filesystem operations

## Testing
- Write tests with `pytest` — use `tmp_path` fixture for temp files
- Name tests `test_<what>_<expected_outcome>` for clarity
- Prefer `assert` over `assertEqual` — pytest rewrites assertions automatically
- Mock external I/O with `unittest.mock.patch` or `pytest-mock`

## Common Patterns
- Use `contextlib.suppress(Exception)` instead of bare `try/except/pass`
- Prefer list/dict comprehensions over `map()`/`filter()` for readability
- Use `__slots__` for performance-critical classes with many instances
- Always close files with `with open(...)` — never manual `.close()`

## Async
- Use `asyncio.to_thread()` to run blocking I/O in async contexts
- Prefer `async with` and `async for` over raw `asyncio.ensure_future`
- Do not mix `asyncio.run()` with an already-running event loop

## Packaging
- Declare dependencies in `pyproject.toml` (PEP 517/518), not just `requirements.txt`
- Pin transitive dependencies with `pip-compile` or `uv lock` for reproducibility
