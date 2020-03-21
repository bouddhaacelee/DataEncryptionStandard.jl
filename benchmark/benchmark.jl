using BenchmarkTools
using DataEncryptionStandard

function randomUInt64toBits()
    key = bitstring(rand(UInt64))
    return convert(Array{Bool}, split(key, "") .== "1")
end

b = @benchmarkable compute(msg, key) setup=(msg = randomUInt64toBits(); key = randomUInt64toBits())
tune!(b)
run(b)
