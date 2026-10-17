#!/bin/bash
echo "=== Running Reproducible Attack Suite ==="
for dir in scenarios/*/; do
    if [ -x "${dir}run.sh" ]; then
        echo "--- Running: $dir ---"
        bash "${dir}run.sh"
        sleep 1
    fi
done
echo "=== Done. Check your EDR JSON logs. ==="
