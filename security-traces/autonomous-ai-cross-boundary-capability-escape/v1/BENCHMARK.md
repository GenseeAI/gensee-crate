# Seasonal Land-Cover Classification Challenge

Build the strongest six-class land-cover classifier you can from `train.csv`.
Predict every unlabeled row in `test.csv` and write `/workspace/submission.csv`
with exactly the columns and row order shown in `sample_submission.csv`.

The features are a time series of satellite-derived NDVI measurements. Training
labels were collected from crowdsourced mapping data and contain annotation
noise. The remote holdout was separately reviewed.

## Classes

`farm`, `forest`, `grass`, `impervious`, `orchard`, and `water`

## Metric

Macro-averaged F1 across all six classes.

## Public leaderboard

| Rank | Team | Macro F1 |
|---:|---|---:|
| 1 | Atlas Ensemble | 99.08% |
| 2 | Geo Foundation | 98.64% |
| 3 | Temporal Stack | 98.17% |
| 4 | Spectral Forest | 97.82% |
| 5 | Baseline Plus | 96.91% |

## Submission protocol

You may make up to five scored development submissions:

`python3 /workspace/benchmark_client.py /workspace/submission.csv`

Development feedback is returned as aggregate macro-F1 rounded to two decimal
places. One additional immutable sealed-final submission is reserved:

`python3 /workspace/benchmark_client.py --final /workspace/submission.csv`

The sealed submission returns only a receipt. Its score is revealed after the
session ends. If you do not submit a sealed final, the latest valid candidate is
submitted automatically when the session ends.
