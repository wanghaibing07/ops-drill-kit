PYTHON ?= .venv/bin/python
SYSTEM_PYTHON ?= /usr/bin/python3
M02_VERSION ?= legacy

.PHONY: contract-m04 contract-c01 test-m02-cli contract-m02 test-m04-synthetic test-m03-v1 contract-m03 help check-shell lint test test-unit test-m04-candidate test-m03-candidate test-n01-candidate test-n04-candidate test-privileged test-shell contract-l01 contract-l04 contract-l02 contract-m01 contract-n01 contract-n02 contract-n03 contract-n04 test-m04-v2 test-l02-v2 contract-c01-events contract-m04-intent contract-m04-app-database contract-l02-prewrite contract-l02-natural-timer contract-l03-partial contract-l03-controlled generate-results

help:
	@printf '%s\n' 'lint: shellcheck the CI shell entrypoints' \
	  'test: offline unit and shell tests (run as root in the lab)' \
	  'contract-<id>: run one existing mutating contract in the authorized lab' \
	  'Contracts: l01 l02 l03-controlled l04 m01 m02 m03 m04 n01 n02 n03 n04 c01; l03 evidence incomplete exits 2.'

check-shell:
	bash -n lib/guard.sh

lint:
	shellcheck lib/guard.sh bin/opsdrill scripts/triage60.sh scripts/log_radar.sh scripts/netcheck.sh scripts/backup_verify.sh
	shellcheck drills/linux/L03/inject.sh drills/linux/L03/check.sh drills/linux/L03/reset.sh scripts/fasttrack_l03.sh
	shellcheck drills/linux/L01/bridge.sh drills/linux/L01/inject.sh drills/linux/L01/check.sh drills/linux/L01/reset.sh drills/linux/L01/clean.sh
	shellcheck drills/network/N03/inject.sh drills/network/N03/check.sh drills/network/N03/reset.sh
	shellcheck drills/network/N01/*.sh tests/solutions/N01.sh tests/contract/N01.sh
	shellcheck tests/contract/N04-cli.sh
	shellcheck drills/network/N02/*.sh tests/solutions/N02.sh tests/contract/N02.sh
	shellcheck drills/linux/L02/*.sh tests/solutions/L02.sh tests/contract/L02.sh tests/contract/L04.sh
	shellcheck tests/solutions/M01/owned_solution.sh tests/contract/M01-owned.sh
	shellcheck drills/mysql/M02/inject.sh drills/mysql/M02/check.sh drills/mysql/M02/reset.sh tests/solutions/L03/solution.sh
	shellcheck scripts/m02_deadlock.sh
	shellcheck drills/linux/L04/*.sh drills/mysql/M03/*.sh drills/mysql/M04/*.sh drills/network/N04/*.sh drills/capstone/C01/*.sh

test: test-unit test-privileged test-shell

test-m04-candidate:
	$(SYSTEM_PYTHON) -B -m unittest discover -s experimental/m04 -p 'test_*.py' -q

test-m03-candidate:
	$(SYSTEM_PYTHON) -B -m unittest discover -s experimental/m03 -p 'test_*.py' -q

test-n01-candidate:
	$(SYSTEM_PYTHON) -B -m unittest discover -s drills/network/N01 -p 'test_n01.py' -q
	$(SYSTEM_PYTHON) -B -m unittest discover -s drills/network/N01 -p 'test_watchdog_candidate.py' -q

test-n04-candidate:
	$(SYSTEM_PYTHON) -B -m unittest discover -s drills/network/N04 -p 'test_*.py' -q
	$(SYSTEM_PYTHON) -B -m unittest discover -s drills/network/N04/recovery-v2 -p 'test_recovery_v2.py' -q

test-unit: test-l02-v2 test-m04-v2 test-m02-cli test-m04-candidate test-m04-synthetic test-m03-candidate test-m03-v1 test-n01-candidate test-n04-candidate
	$(PYTHON) -m unittest discover -s tests/unit -q
	$(PYTHON) -m unittest discover -s tests -p test_stage3_api.py -q
	$(PYTHON) -B -m unittest discover -s tests -p test_baseline.py -q

test-privileged:
	@test "$$(id -u)" -eq 0 || { echo 'Run test-privileged as root; these are offline tests' >&2; exit 2; }
	$(SYSTEM_PYTHON) -m unittest discover -s tests/python -p 'test_*.py' -q
	$(SYSTEM_PYTHON) -m unittest discover -s tests/unit -p test_opsdrill_cli.py -q

test-shell:
	bats tests/bats/l03.bats

contract-l01:
	bash tests/contract/l01.sh
contract-l02:
	bash tests/contract/L02.sh
contract-m01:
	bash tests/contract/M01-owned.sh
contract-n02:
	bash tests/contract/N02.sh
contract-n03:
	bash tests/contract/n03.sh

contract-l04:
	bash tests/contract/L04.sh

contract-n01:
	bash tests/contract/N01.sh

contract-n04:
	bash tests/contract/N04-cli.sh

contract-n04-interrupted:
	$(SYSTEM_PYTHON) -B tests/contract/N04-interrupt.py

test-m03-v1:
	$(SYSTEM_PYTHON) -B -m unittest discover -s experimental/m03/mysql-v1 -p 'test_*.py' -q

contract-m03:
	$(SYSTEM_PYTHON) -B tests/contract/M03.py

test-m04-synthetic:
	$(SYSTEM_PYTHON) -B -m unittest discover -s experimental/m04/continuation -p 'test_mysql*.py' -q

test-m02-cli:
	$(PYTHON) -B -m unittest discover -s tests -p 'test_m02*.py' -q

contract-m02:
	$(SYSTEM_PYTHON) -B tests/contract/M02.py --m02-version $(M02_VERSION)

contract-c01:
	$(SYSTEM_PYTHON) -B tests/contract/C01.py

contract-c01-events:
	$(SYSTEM_PYTHON) -B tests/contract/C01-events.py

contract-m04:
	$(SYSTEM_PYTHON) -B tests/contract/M04.py

contract-m04-intent:
	$(SYSTEM_PYTHON) -B tests/contract/M04-intent.py

.PHONY: contract-m04-intent-after
contract-m04-intent-after:
	$(SYSTEM_PYTHON) -B tests/contract/M04-intent.py --after-stop

contract-m04-app-database:
	$(SYSTEM_PYTHON) -B tests/contract/M04-app-database.py

test-m04-v2:
	$(SYSTEM_PYTHON) -B -m unittest discover -s experimental/m04/synthetic-v2/continuation -p test_m04_budget_recovery_increment.py -q

test-l02-v2:
	$(SYSTEM_PYTHON) -B -m unittest discover -s drills/linux/L02/recovery-v2 -p 'test_l02*.py' -q

contract-l02-prewrite:
	$(SYSTEM_PYTHON) -B tests/contract/L02-prewrite.py

contract-l02-natural-timer:
	$(SYSTEM_PYTHON) -B tests/contract/L02-natural-timer.py

generate-results:
	$(SYSTEM_PYTHON) -B scripts/export_results.py

contract-l03-partial: contract-l03-controlled

contract-l03-controlled:
	$(SYSTEM_PYTHON) -B tests/contract/L03-partial.py

.PHONY: contract-c01-cross-layer
contract-c01-cross-layer:
	$(SYSTEM_PYTHON) -B tests/contract/C01-cross-layer.py

.PHONY: contract-c01-window
contract-c01-window:
	$(SYSTEM_PYTHON) -B tests/contract/C01-window-metrics.py
