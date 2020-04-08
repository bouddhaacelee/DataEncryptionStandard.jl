using DataEncryptionStandard
using Test

@testset "DataEncryptionStandard.jl" begin
    #=
    key:       133457799bbcdff1
    message:   0123456789abcdef
    encrypted: 85e813540f0ab405
    =#
    msg_val = fromStringtoBits("0123456789abcdef")
    msg = falses(64, 2)
    msg[:, 1] = msg_val
    msg[:, 2] = msg_val
    key_val = fromStringtoBits("133457799bbcdff1")
    key = falses(64, 2)
    key[:, 1] = key_val
    key[:, 2] = key_val
    out = compute_many(msg, key)
    #test de la valeur de la sub_key pour chaque tour
    expected_key = BitArray([0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0])
    @test expected_key == out["SUB_KEY"][:, 1, 1]
    # @test out == fromStringtoBits("85e813540f0ab405")
end
