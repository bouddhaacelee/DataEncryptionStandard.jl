include("sboxesArray.jl")

function pack48bitsby6(data_to_packs::BitArray)
    data_packed = zeros(UInt8, 8, size(data_to_packs, 2))
    for x = 1:8
        data_packed[x, :] = data_to_packs[6*x - 5, :]
        for i in 2:6
            data_packed[x, :] .<<= 1
            data_packed[x, :] .|= data_to_packs[i + (x-1)*6, :]
        end
    end
    data_packed .+= 1
    return data_packed
end

"""
compute(msg, key)

Compute the DES for msg with key. 

# Arguments
    * msg: the plaintext to encrypt, type : Array{Bool, 1}
    * key: the key used for encryption, type : Array{Bool, 1} 

#Output
    * cipher: result of the DES, , type : Array{Bool, 1}

# Examples
```julia-repl
julia> msg = fromStringtoBits("8787878787878787")
julia> key = fromStringtoBits("0e329232ea6d0d73")
julia> out = compute(msg, key)
julia> out == fromStringtoBits("0000000000000000")
true
```
"""
function compute_many(plaintext::BitArray, key::BitArray)
    @assert size(key) == size(key)
    intermediate_values = Dict{String, BitArray}()
    intermediate_values["SUB_KEY"]  = BitArray{3}(undef, 48, size(key, 2), 16)
    intermediate_values["L_&_R"]    = BitArray{3}(undef, 64, size(plaintext, 2), 16)
    intermediate_values["EXP_R"]    = BitArray{3}(undef, 48, size(plaintext, 2), 16)
    intermediate_values["SBOX_IN"]  = BitArray{3}(undef, 48, size(plaintext, 2), 16)
    intermediate_values["SBOX_OUT"] = BitArray{3}(undef, 32, size(plaintext, 2), 16)
    intermediate_values["FP_IN"]    = BitArray{2}(undef, 64, size(plaintext, 2))
    intermediate_values["CIPHER"]   = BitArray{2}(undef, 64, size(plaintext, 2))
    # KEY derivation
    intermediate_values["SUB_KEY"][:, :, 1] = key[SUB_KEY_1_P, :]
    intermediate_values["SUB_KEY"][:, :, 2] = key[SUB_KEY_2_P, :]
    intermediate_values["SUB_KEY"][:, :, 3] = key[SUB_KEY_3_P, :]
    intermediate_values["SUB_KEY"][:, :, 4] = key[SUB_KEY_4_P, :]
    intermediate_values["SUB_KEY"][:, :, 5] = key[SUB_KEY_5_P, :]
    intermediate_values["SUB_KEY"][:, :, 6] = key[SUB_KEY_6_P, :]
    intermediate_values["SUB_KEY"][:, :, 7] = key[SUB_KEY_7_P, :]
    intermediate_values["SUB_KEY"][:, :, 8] = key[SUB_KEY_8_P, :]
    intermediate_values["SUB_KEY"][:, :, 9] = key[SUB_KEY_9_P, :]
    intermediate_values["SUB_KEY"][:, :, 10] = key[SUB_KEY_10_P, :]
    intermediate_values["SUB_KEY"][:, :, 11] = key[SUB_KEY_11_P, :]
    intermediate_values["SUB_KEY"][:, :, 12] = key[SUB_KEY_12_P, :]
    intermediate_values["SUB_KEY"][:, :, 13] = key[SUB_KEY_13_P, :]
    intermediate_values["SUB_KEY"][:, :, 14] = key[SUB_KEY_14_P, :]
    intermediate_values["SUB_KEY"][:, :, 15] = key[SUB_KEY_15_P, :]
    intermediate_values["SUB_KEY"][:, :, 16] = key[SUB_KEY_16_P, :]
    # Initial permutation
    intermediate_values["L_&_R"][:, :, 1] = plaintext[IPbits, :]
    # round 1
    intermediate_values["EXP_R"][:, :, 1] = intermediate_values["L_&_R"][EXP_R, :, 1]
    intermediate_values["SBOX_IN"][:, :, 1] = intermediate_values["EXP_R"][:, :, 1] .⊻ intermediate_values["SUB_KEY"][:, :, 1]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 1])
    intermediate_values["SBOX_OUT"][1:4, :, 1] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 1] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 1] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 1] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 1] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 1] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 1] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 1] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 2] = intermediate_values["SBOX_OUT"][P, :, 1] .⊻ intermediate_values["L_&_R"][1:32, :, 1]
    intermediate_values["L_&_R"][1:32, :, 2] = intermediate_values["L_&_R"][33:64, :, 1]
    
    # round 2
    intermediate_values["EXP_R"][:, :, 2] = intermediate_values["L_&_R"][EXP_R, :, 2]
    intermediate_values["SBOX_IN"][:, :, 2] = intermediate_values["EXP_R"][:, :, 2] .⊻ intermediate_values["SUB_KEY"][:, :, 2]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 2])
    intermediate_values["SBOX_OUT"][1:4, :, 2] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 2] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 2] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 2] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 2] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 2] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 2] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 2] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 3] = intermediate_values["SBOX_OUT"][P, :, 2] .⊻ intermediate_values["L_&_R"][1:32, :, 2]
    intermediate_values["L_&_R"][1:32, :, 3] = intermediate_values["L_&_R"][33:64, :, 2]

    # round 3
    intermediate_values["EXP_R"][:, :, 3] = intermediate_values["L_&_R"][EXP_R, :, 3]
    intermediate_values["SBOX_IN"][:, :, 3] = intermediate_values["EXP_R"][:, :, 3] .⊻ intermediate_values["SUB_KEY"][:, :, 3]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 3])
    intermediate_values["SBOX_OUT"][1:4, :, 3] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 3] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 3] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 3] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 3] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 3] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 3] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 3] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 4] = intermediate_values["SBOX_OUT"][P, :, 3] .⊻ intermediate_values["L_&_R"][1:32, :, 3]
    intermediate_values["L_&_R"][1:32, :, 4] = intermediate_values["L_&_R"][33:64, :, 3]

    # round 4
    intermediate_values["EXP_R"][:, :, 4] = intermediate_values["L_&_R"][EXP_R, :, 4]
    intermediate_values["SBOX_IN"][:, :, 4] = intermediate_values["EXP_R"][:, :, 4] .⊻ intermediate_values["SUB_KEY"][:, :, 4]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 4])
    intermediate_values["SBOX_OUT"][1:4, :, 4] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 4] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 4] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 4] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 4] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 4] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 4] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 4] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 5] = intermediate_values["SBOX_OUT"][P, :, 4] .⊻ intermediate_values["L_&_R"][1:32, :, 4]
    intermediate_values["L_&_R"][1:32, :, 5] = intermediate_values["L_&_R"][33:64, :, 4]
    # round 5
    intermediate_values["EXP_R"][:, :, 5] = intermediate_values["L_&_R"][EXP_R, :, 5]
    intermediate_values["SBOX_IN"][:, :, 5] = intermediate_values["EXP_R"][:, :, 5] .⊻ intermediate_values["SUB_KEY"][:, :, 5]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 5])
    intermediate_values["SBOX_OUT"][1:4, :, 5] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 5] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 5] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 5] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 5] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 5] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 5] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 5] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 6] = intermediate_values["SBOX_OUT"][P, :, 5] .⊻ intermediate_values["L_&_R"][1:32, :, 5]
    intermediate_values["L_&_R"][1:32, :, 6] = intermediate_values["L_&_R"][33:64, :, 5]
    
    # round 6
    intermediate_values["EXP_R"][:, :, 6] = intermediate_values["L_&_R"][EXP_R, :, 6]
    intermediate_values["SBOX_IN"][:, :, 6] = intermediate_values["EXP_R"][:, :, 6] .⊻ intermediate_values["SUB_KEY"][:, :, 6]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 6])
    intermediate_values["SBOX_OUT"][1:4, :, 6] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 6] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 6] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 6] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 6] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 6] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 6] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 6] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 7] = intermediate_values["SBOX_OUT"][P, :, 6] .⊻ intermediate_values["L_&_R"][1:32, :, 6]
    intermediate_values["L_&_R"][1:32, :, 7] = intermediate_values["L_&_R"][33:64, :, 6]

    # round 7
    intermediate_values["EXP_R"][:, :, 7] = intermediate_values["L_&_R"][EXP_R, :, 7]
    intermediate_values["SBOX_IN"][:, :, 7] = intermediate_values["EXP_R"][:, :, 7] .⊻ intermediate_values["SUB_KEY"][:, :, 7]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 7])
    intermediate_values["SBOX_OUT"][1:4, :, 7] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 7] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 7] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 7] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 7] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 7] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 7] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 7] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 8] = intermediate_values["SBOX_OUT"][P, :, 7] .⊻ intermediate_values["L_&_R"][1:32, :, 7]
    intermediate_values["L_&_R"][1:32, :, 8] = intermediate_values["L_&_R"][33:64, :, 7]

    # round 8
    intermediate_values["EXP_R"][:, :, 8] = intermediate_values["L_&_R"][EXP_R, :, 8]
    intermediate_values["SBOX_IN"][:, :, 8] = intermediate_values["EXP_R"][:, :, 8] .⊻ intermediate_values["SUB_KEY"][:, :, 8]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 8])
    intermediate_values["SBOX_OUT"][1:4, :, 8] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 8] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 8] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 8] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 8] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 8] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 8] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 8] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 9] = intermediate_values["SBOX_OUT"][P, :, 8] .⊻ intermediate_values["L_&_R"][1:32, :, 8]
    intermediate_values["L_&_R"][1:32, :, 9] = intermediate_values["L_&_R"][33:64, :, 8]
    
    # round 9
    intermediate_values["EXP_R"][:, :, 9] = intermediate_values["L_&_R"][EXP_R, :, 9]
    intermediate_values["SBOX_IN"][:, :, 9] = intermediate_values["EXP_R"][:, :, 9] .⊻ intermediate_values["SUB_KEY"][:, :, 9]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 9])
    intermediate_values["SBOX_OUT"][1:4, :, 9] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 9] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 9] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 9] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 9] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 9] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 9] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 9] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 10] = intermediate_values["SBOX_OUT"][P, :, 9] .⊻ intermediate_values["L_&_R"][1:32, :, 9]
    intermediate_values["L_&_R"][1:32, :, 10] = intermediate_values["L_&_R"][33:64, :, 9]

    # round 10
    intermediate_values["EXP_R"][:, :, 10] = intermediate_values["L_&_R"][EXP_R, :, 10]
    intermediate_values["SBOX_IN"][:, :, 10] = intermediate_values["EXP_R"][:, :, 10] .⊻ intermediate_values["SUB_KEY"][:, :, 10]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 10])
    intermediate_values["SBOX_OUT"][1:4, :, 10] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 10] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 10] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 10] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 10] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 10] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 10] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 10] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 11] = intermediate_values["SBOX_OUT"][P, :, 10] .⊻ intermediate_values["L_&_R"][1:32, :, 10]
    intermediate_values["L_&_R"][1:32, :, 11] = intermediate_values["L_&_R"][33:64, :, 10]

    # round 11
    intermediate_values["EXP_R"][:, :, 11] = intermediate_values["L_&_R"][EXP_R, :, 11]
    intermediate_values["SBOX_IN"][:, :, 11] = intermediate_values["EXP_R"][:, :, 11] .⊻ intermediate_values["SUB_KEY"][:, :, 11]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 11])
    intermediate_values["SBOX_OUT"][1:4, :, 11] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 11] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 11] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 11] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 11] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 11] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 11] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 11] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 12] = intermediate_values["SBOX_OUT"][P, :, 11] .⊻ intermediate_values["L_&_R"][1:32, :, 11]
    intermediate_values["L_&_R"][1:32, :, 12] = intermediate_values["L_&_R"][33:64, :, 11]

    # round 12
    intermediate_values["EXP_R"][:, :, 12] = intermediate_values["L_&_R"][EXP_R, :, 12]
    intermediate_values["SBOX_IN"][:, :, 12] = intermediate_values["EXP_R"][:, :, 12] .⊻ intermediate_values["SUB_KEY"][:, :, 12]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 12])
    intermediate_values["SBOX_OUT"][1:4, :, 12] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 12] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 12] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 12] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 12] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 12] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 12] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 12] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 13] = intermediate_values["SBOX_OUT"][P, :, 12] .⊻ intermediate_values["L_&_R"][1:32, :, 12]
    intermediate_values["L_&_R"][1:32, :, 13] = intermediate_values["L_&_R"][33:64, :, 12]

    # round 13
    intermediate_values["EXP_R"][:, :, 13] = intermediate_values["L_&_R"][EXP_R, :, 13]
    intermediate_values["SBOX_IN"][:, :, 13] = intermediate_values["EXP_R"][:, :, 13] .⊻ intermediate_values["SUB_KEY"][:, :, 13]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 13])
    intermediate_values["SBOX_OUT"][1:4, :, 13] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 13] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 13] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 13] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 13] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 13] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 13] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 13] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 14] = intermediate_values["SBOX_OUT"][P, :, 13] .⊻ intermediate_values["L_&_R"][1:32, :, 13]
    intermediate_values["L_&_R"][1:32, :, 14] = intermediate_values["L_&_R"][33:64, :, 13]

    # round 14
    intermediate_values["EXP_R"][:, :, 14] = intermediate_values["L_&_R"][EXP_R, :, 14]
    intermediate_values["SBOX_IN"][:, :, 14] = intermediate_values["EXP_R"][:, :, 14] .⊻ intermediate_values["SUB_KEY"][:, :, 14]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 14])
    intermediate_values["SBOX_OUT"][1:4, :, 14] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 14] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 14] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 14] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 14] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 14] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 14] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 14] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 15] = intermediate_values["SBOX_OUT"][P, :, 14] .⊻ intermediate_values["L_&_R"][1:32, :, 14]
    intermediate_values["L_&_R"][1:32, :, 15] = intermediate_values["L_&_R"][33:64, :, 14]

    # round 15
    intermediate_values["EXP_R"][:, :, 15] = intermediate_values["L_&_R"][EXP_R, :, 15]
    intermediate_values["SBOX_IN"][:, :, 15] = intermediate_values["EXP_R"][:, :, 15] .⊻ intermediate_values["SUB_KEY"][:, :, 15]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 15])
    intermediate_values["SBOX_OUT"][1:4, :, 15] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 15] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 15] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 15] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 15] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 15] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 15] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 15] = ARRAY_SBOX_8[:, a[8, :]]
    
    intermediate_values["L_&_R"][33:64, :, 16] = intermediate_values["SBOX_OUT"][P, :, 15] .⊻ intermediate_values["L_&_R"][1:32, :, 15]
    intermediate_values["L_&_R"][1:32, :, 16] = intermediate_values["L_&_R"][33:64, :, 15]

    # round 16
    intermediate_values["EXP_R"][:, :, 16] = intermediate_values["L_&_R"][EXP_R, :, 16]
    intermediate_values["SBOX_IN"][:, :, 16] = intermediate_values["EXP_R"][:, :, 16] .⊻ intermediate_values["SUB_KEY"][:, :, 16]
    
    a = pack48bitsby6(intermediate_values["SBOX_IN"][:, :, 16])
    intermediate_values["SBOX_OUT"][1:4, :, 16] = ARRAY_SBOX_1[:, a[1, :]]
    intermediate_values["SBOX_OUT"][5:8, :, 16] = ARRAY_SBOX_2[:, a[2, :]]
    intermediate_values["SBOX_OUT"][9:12, :, 16] = ARRAY_SBOX_3[:, a[3, :]]
    intermediate_values["SBOX_OUT"][13:16, :, 16] = ARRAY_SBOX_4[:, a[4, :]]
    intermediate_values["SBOX_OUT"][17:20, :, 16] = ARRAY_SBOX_5[:, a[5, :]]
    intermediate_values["SBOX_OUT"][21:24, :, 16] = ARRAY_SBOX_6[:, a[6, :]]
    intermediate_values["SBOX_OUT"][25:28, :, 16] = ARRAY_SBOX_7[:, a[7, :]]
    intermediate_values["SBOX_OUT"][29:32, :, 16] = ARRAY_SBOX_8[:, a[8, :]]

    intermediate_values["FP_IN"][1:32, :] = intermediate_values["SBOX_OUT"][P, :, 16] .⊻ intermediate_values["L_&_R"][1:32, :, 16]
    intermediate_values["FP_IN"][33:64, :] = intermediate_values["L_&_R"][33:64, :, 16]
    
    # Final permutation
    intermediate_values["CIPHER"] = intermediate_values["FP_IN"][FP, :]
    # end
    return intermediate_values
    
    
end