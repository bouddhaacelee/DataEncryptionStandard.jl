using BenchmarkTools
using DataEncryptionStandard
msg = randomUInt64toBits()
key = randomUInt64toBits()
compute(msg, key)

b = @benchmarkable compute(msg, key) setup=(msg = randomUInt64toBits(); key = randomUInt64toBits())
tune!(b)
run(b)
