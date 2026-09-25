# Comparison of runs (ablations)

| Run | Reports | Recall | FPR | Precision | F1 | Accuracy | Balanced acc. | Accuracy end-to-end |
|---|---|---|---|---|---|---|---|---|
| `v12_llm` no retrieval (LLM only) | 591/591 | 96.2% | 0.8% | 99.8% | 97.9% | 96.9% | 97.7% | 96.1% |
| `v12_policy` security knowledge base only | 591/591 | 96.2% | 4.6% | 98.5% | 97.3% | 96.0% | 95.8% | 95.3% |
| `v12_samples` malware samples only | 591/591 | 96.6% | 3.1% | 99.0% | 97.8% | 96.7% | 96.8% | 95.9% |
| `v12_sum` full system (samples + policies) | 591/591 | 97.1% | 6.2% | 98.1% | 97.6% | 96.3% | 95.5% | 95.6% |

LLM stage: without the packages that have no Behavior Chains; end-to-end: with them (malware = FN, benign = TN).
