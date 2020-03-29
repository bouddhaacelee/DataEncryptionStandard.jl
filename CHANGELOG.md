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
Test Summary:             | Pass  Total
DataEncryptionStandard.jl |    6      6
Test.DefaultTestSet("DataEncryptionStandard.jl", Any[], 6, false)

BenchmarkTools.Trial: 
  memory estimate:  13.70 KiB
  allocs estimate:  237
  --------------
  minimum time:     13.655 μs (0.00% GC)
  median time:      14.317 μs (0.00% GC)
  mean time:        16.940 μs (8.92% GC)
  maximum time:     4.330 ms (98.51% GC)
  --------------
  samples:          10000
  evals/sample:     1