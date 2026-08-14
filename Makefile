.PHONY: lab-test lab-prepare lab-start lab-reset lab-smoke lab-full lab-stop lab-clean

LAB = python3 scripts/lab/qemu_lab.py

lab-test:
	python3 -m unittest -v tests/lab/test_qemu_lab.py
	bash -n scripts/lab/guest-runner.sh
	shellcheck scripts/lab/guest-runner.sh

lab-prepare:
	$(LAB) prepare

lab-start:
	$(LAB) start

lab-reset:
	$(LAB) reset

lab-smoke:
	$(LAB) run --mode smoke --output lab-results

lab-full:
	$(LAB) run --mode full --output lab-results

lab-stop:
	$(LAB) stop

lab-clean:
	$(LAB) cleanup
