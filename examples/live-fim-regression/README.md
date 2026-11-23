# Live FIM rule regression

Seori ran `fim-file-created` in live mode on a standard GitHub-hosted `ubuntu-24.04` runner with Wazuh Manager and Agent 4.14.10-1 and Indexer 4.14.10. [Successful Actions run](https://github.com/dakonya/Seori/actions/runs/45182772256) · [Original JSON and HTML reports](https://github.com/dakonya/Seori/actions/runs/45182772256/artifacts/14822681987)

The original JSON, HTML and workflow logs were published under the name DetectionCI.

| Phase | Seori verdict | Expected rule | Observed rule | Matches | Cleanup |
| --- | --- | --- | --- | ---: | --- |
| Baseline | PASS | `100200` | `100200` | 1 | Confirmed |
| Regression | FAIL | `100200` | `554` | 0 | Confirmed |
| Restored | PASS | `100200` | `100200` | 1 | Confirmed |

All phases used Wazuh agent `001` and a separate file named for the run ID.

- Baseline run ID `dc949793-f6cd-4ceb-8229-43a5a0670720`
- Regression run ID `f9eb39ca-f424-49d0-87e7-7a79ab7ee2dd`
- Restored run ID `d789cfd5-8d35-47e8-b347-201c9cce4de6`

Matches counts alerts for rule `100200`. The independent Indexer query found rule `554` for the regression file's `added` event during that run.

The Manager loaded the modified XML for Regression and restored the original XML for Restored. The recorded SHA-256 values identify the two configurations.

- Baseline and Restored `1f79e093d87e90167e64587e91ab4b49ddd9410739406bcd581784ea15885f95`
- Regression `5c5cbdbd31743991085d38967f64ce59e8c9a1888bb2621caef028e1a67c0a04`

The independent Indexer query is preserved with the regression run ID, time window and native report SHA-256. [Indexer evidence](regression-evidence.json)
