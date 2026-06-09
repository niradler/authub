.PHONY: sync fmt lint type test check cov clean publish

sync:
	uv sync --dev --all-extras

fmt:
	uv run ruff format .

lint:
	uv run ruff check .

type:
	uv run mypy

test:
	uv run pytest -q

check: fmt lint type test

cov:
	uv run pytest --cov --cov-report=term-missing -q

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage

publish:
	pwsh -NoProfile -Command "$$pypircPath = Join-Path $$HOME '.pypirc'; if (-not (Test-Path $$pypircPath)) { throw '.pypirc not found' }; $$sections = @{}; $$currentSection = $$null; foreach ($$rawLine in Get-Content $$pypircPath) { $$line = $$rawLine.Trim(); if (-not $$line -or $$line.StartsWith('#') -or $$line.StartsWith(';')) { continue }; if ($$line -match '^\[(.+)\]$$') { $$currentSection = $$matches[1].Trim(); if (-not $$sections.ContainsKey($$currentSection)) { $$sections[$$currentSection] = @{} }; continue }; if ($$currentSection -and $$line -match '^(?<key>[^=]+?)\s*=\s*(?<value>.*)$$') { $$key = $$matches['key'].Trim(); $$value = $$matches['value'].Trim(); $$sections[$$currentSection][$$key] = $$value } }; if ($$sections.ContainsKey('pypi') -and $$sections['pypi'].ContainsKey('username') -and $$sections['pypi'].ContainsKey('password')) { $$publishSection = 'pypi' } else { $$match = $$sections.GetEnumerator() | Where-Object { $$_.Value.ContainsKey('username') -and $$_.Value.ContainsKey('password') } | Select-Object -First 1; if (-not $$match) { throw 'No publish credentials section with username/password found in .pypirc' }; $$publishSection = $$match.Key }; $$env:UV_PUBLISH_USERNAME = $$sections[$$publishSection]['username']; $$env:UV_PUBLISH_PASSWORD = $$sections[$$publishSection]['password']; $$publishArgs = @(); if ($$sections[$$publishSection].ContainsKey('repository') -and -not [string]::IsNullOrWhiteSpace($$sections[$$publishSection]['repository'])) { $$publishArgs += @('--publish-url', $$sections[$$publishSection]['repository']) }; uv publish $$publishArgs"
