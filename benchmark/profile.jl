using ProfileView
using DataEncryptionStandard

msg = fromStringtoBits("8787878787878787")
key = fromStringtoBits("0e329232ea6d0d73")

function compute_ntimes(ntimes)
    for i in 1:1:ntimes
        out = compute(msg, key)
    end
end

@profview compute_ntimes(1)  # run once to trigger compilation (ignore this one)
@profview compute_ntimes(1000000)