# Usage Report — Ghost Data Still Exists

## Full-Dataset Execution

- Language: Python
- Approach: Deterministic, rule-based processing
- Input: `dataset/deletion_requests.csv`
- Requests processed: 518
- Output: `output.csv`
- Output data rows: 518
- Validation errors: 0, according to the recorded validation result

## Model and API Usage

- External model provider: None
- Model name: Not applicable
- External model calls: 0
- External API calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total cost: $0
- Estimated average cost per request: $0
- Per-model totals: Not applicable; no model was used

## Sample Evaluation

- Public sample requests: 32
- Status accuracy: 32/32 (100%)
- Exact step-array match: 32/32 (100%)
- Synthetic tests reported as passing: 7

These sample results do not establish accuracy on hidden evaluation cases.

## Reproduction

Run from the repository root:

```cmd
python code\main.py
python code\evaluation\main.py
```

The first command generates the prediction output. The second runs the public sample evaluation.