# Change Log

## branch -> release/naive_DES

|Test Summary:             | Pass  |Total|
|--------------------------|-------|-----|
|DataEncryptionStandard.jl |    6  |    6|

BenchmarkTools
* memory estimate:  165.73 KiB
* allocs estimate:  519
* minimum time:     60.263 μs (0.00% GC)
* median time:      63.630 μs (0.00% GC)
* mean time:        82.858 μs (19.72% GC)
* maximum time:     36.937 ms (99.59% GC)
* samples:          10000
* evals/sample:     1

Set as master

## Increase speed
|Test Summary:             | Pass  |Total|
|--------------------------|-------|-----|
|DataEncryptionStandard.jl |    6  |    6|

BenchmarkTools
* memory estimate:  13.70 KiB
* allocs estimate:  237
* minimum time:     13.655 μs (0.00% GC)
* median time:      14.317 μs (0.00% GC)
* mean time:        16.940 μs (8.92% GC)
* maximum time:     4.330 ms (98.51% GC)
* samples:          10000
* evals/sample:     1

## Add compute_many
|Test Summary:             | Pass | Total|
|--------------------------|------|------|  
|DataEncryptionStandard.jl |   38 |    38|

BenchmarkTools for 100000 DES
* memory estimate:  290.30 MiB
* allocs estimate:  6901
* minimum time:     1.317 s (0.24% GC)
* median time:      1.410 s (4.55% GC)
* mean time:        1.389 s (4.55% GC)
* maximum time:     1.421 s (8.53% GC)
* samples:          4
* evals/sample:     1