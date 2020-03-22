using DataEncryptionStandard
using Test

@testset "DataEncryptionStandard.jel" begin
    # Write your own tests here.
    #= cast
    key:       0e329232ea6d0d73
    =#
    # 0000111000110010100100100011001011101010011011010000110101110011
    key_from_string = fromStringtoBits("0e329232ea6d0d73")
    key = [false, false, false, false, true, true, true, false, false, false, true, true, false, false, true, false, true, false, false, true, false, false, true, false, false, false, true, true, false, false, true, false, true, true, true, false, true, false, true, false, false, true, true, false, true, true, false, true, false, false, false, false, true, true, false, true, false, true, true, true, false, false, true, true]
    @test key == key_from_string
    #=
    key:       0e329232ea6d0d73
    message:   8787878787878787
    encrypted: 0000000000000000
    =#
    msg = fromStringtoBits("8787878787878787")
    key = fromStringtoBits("0e329232ea6d0d73")
    out = compute(msg, key)
    @test out == fromStringtoBits("0000000000000000")
    #=
    key:       133457799bbcdff1
    message:   0123456789abcdef
    encrypted: 85e813540f0ab405
    =#
    msg = fromStringtoBits("0123456789abcdef")
    key = fromStringtoBits("133457799bbcdff1")
    out = compute(msg, key)
    @test out == fromStringtoBits("85e813540f0ab405")
    #=
    key:       AABB09182736CCDD
    message:   0123456ABCD13253
    encrypted: C0B7A8D05F3A829C
    =#
    msg = fromStringtoBits("123456ABCD132536")
    key = fromStringtoBits("AABB09182736CCDD")
    out = compute(msg, key)
    @test out == fromStringtoBits("C0B7A8D05F3A829C")
    #=
    key:       22234512987ABB23
    message:   0000000000000000 
    encrypted: 4789FD476E82A5F1 
    =#
    msg = fromStringtoBits("0000000000000000")
    key = fromStringtoBits("22234512987ABB23")
    out = compute(msg, key)
    @test out == fromStringtoBits("4789FD476E82A5F1")
        #=
    key:       22234512987ABB23
    message:   0000000000000001
    encrypted: 0A4ED5C15A63FEA3
    =#
    msg = fromStringtoBits("0000000000000001")
    key = fromStringtoBits("22234512987ABB23")
    out = compute(msg, key)
    @test out == fromStringtoBits("0A4ED5C15A63FEA3")
end
