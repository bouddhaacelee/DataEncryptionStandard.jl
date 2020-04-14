using BenchmarkTools
using DataEncryptionStandard

function get(count)
    msg_val = fromStringtoBits("0123456789abcdef")
    msg = falses(64, count)
    for i in 1:count
        msg[:, i] = msg_val
    end
    return msg
end

b = @benchmarkable compute_many(msg, key) setup=(msg = get(100000); key = get(100000))
tune!(b)
run(b)
