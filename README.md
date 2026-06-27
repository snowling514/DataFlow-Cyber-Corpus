# DataFlow Cyber Corpus Experiments

This repository contains DataFlow-based experiments for cybersecurity corpus construction.

## Contents

- `scripts/`: reproducible scripts for DataFlow case experiments, public source sampling, and V1 corpus construction.
- `source_sample_corpus/`: sampled public cybersecurity source records from CISA KEV, NVD, FIRST EPSS, CVEProject cvelistV5, CICIDS2017, and UNSW-NB15.
- `cyber_training_corpus_v1/`: V1 raw-source, QA, and SFT-style cybersecurity training corpus files.
- `experiments/`: intermediate DataFlow case inputs and outputs.

Text reports are intentionally excluded from Git by `*.txt`.

## Setup

Create and activate a Python environment, then install DataFlow:

```powershell
pip install open-dataflow
```

Run the V1 corpus build:

```powershell
python scripts/build_training_corpus_v1.py
```
