using BenchmarkTools
using DataEncryptionStandard

b = @benchmarkable compute(msg, key) setup=(msg = randomUInt64toBits(); key = randomUInt64toBits())
tune!(b)
run(b)
