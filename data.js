window.BENCHMARK_DATA = {
  "lastUpdate": 1787702314662,
  "repoUrl": "https://github.com/cplieger/auth",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "74960626aaac74ea43d2e5784b963da3b51d319e",
          "message": "chore(sync): synced file(s) with cplieger/ci (#394)\n\nCo-authored-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-25T08:09:02Z",
          "url": "https://github.com/cplieger/auth/commit/74960626aaac74ea43d2e5784b963da3b51d319e"
        },
        "date": 1787702314359,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkAuthenticate/api_key_header - B/op",
            "value": 504,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/api_key_header - allocs/op",
            "value": 6,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/api_key_header",
            "value": 496.4,
            "range": "± 3.65",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/no_credentials - B/op",
            "value": 24,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/no_credentials - allocs/op",
            "value": 1,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/no_credentials",
            "value": 68.06,
            "range": "± 2.12",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/session_cookie - B/op",
            "value": 656,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/session_cookie - allocs/op",
            "value": 7,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkAuthenticate/session_cookie",
            "value": 667.95,
            "range": "± 11.45",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      }
    ]
  }
}