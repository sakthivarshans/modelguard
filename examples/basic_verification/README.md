# Basic verification example

A tiny synthetic "model directory" used to exercise the full Phase 1
workflow end to end.

```bash
modelguard inspect ./model
modelguard manifest ./model -o model.manifest.json --model-id toy-classifier --version 1.0.0
modelguard mbom generate model.manifest.json -o model.bom.json
modelguard keygen --identity dev@example.com --output-dir ./keys
modelguard sign ./model \
  --manifest model.manifest.json --mbom model.bom.json \
  --key ./keys/dev_at_example.com.modelguard.key --identity dev@example.com \
  -o model.sig.json
modelguard verify ./model --mbom model.bom.json --signature model.sig.json
```

Then try tampering with the model to see verification fail closed:

```bash
echo "tampered" >> ./model/config.json
modelguard verify ./model --mbom model.bom.json --signature model.sig.json
echo "exit code: $?"   # 2 (denied)
```
