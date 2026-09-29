# Comparison of runs (ablations)

| Run | Reports | Recall | FPR | Precision | F1 | Accuracy | Balanced acc. | Accuracy end-to-end |
|---|---|---|---|---|---|---|---|---|
| `v14_sum` full system (samples + policies) | 950/950 | 96.8% | 1.5% | 98.8% | 97.8% | 97.6% | 97.7% | 97.1% |
| `v14_samples` malware samples only | 950/950 | 96.4% | 1.5% | 98.8% | 97.6% | 97.3% | 97.5% | 96.8% |
| `v14_policy` security knowledge base only | 950/950 | 96.2% | 1.7% | 98.6% | 97.4% | 97.1% | 97.2% | 96.6% |
| `v14_llm` no retrieval (LLM only) | 950/950 | 95.5% | 1.2% | 99.1% | 97.2% | 96.9% | 97.2% | 96.5% |

LLM stage: without the packages that have no Behavior Chains; end-to-end: with them (malware = FN, benign = TN).
