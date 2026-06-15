# Glass Box — convenience targets. Everything works with stdlib only.
PY ?= python

.PHONY: run open demo test surface armor verify clean

run:            ## Run the full investigation -> out/report.html
	$(PY) run.py

open:           ## Run and open the report in a browser
	$(PY) run.py --open

demo: open      ## Alias for the live demo

surface:        ## Print the typed read-only MCP tool surface (0 write/shell tools)
	$(PY) -m glassbox.mcp_server --list

armor:          ## Run the PromptArmor injection-corpus self-test
	$(PY) -m glassbox.promptarmor

verify:         ## Re-verify the ledger hash chain of the last run
	$(PY) -c "from glassbox.claimchain import ClaimChain; import json; print(json.dumps(ClaimChain('out/ledger.jsonl').verify_chain(), indent=2))"

test:           ## Run the test suite (unittest; no pytest needed)
	$(PY) -m unittest discover -s tests -v

clean:          ## Remove run artifacts
	rm -rf out __pycache__ glassbox/__pycache__ tests/__pycache__
