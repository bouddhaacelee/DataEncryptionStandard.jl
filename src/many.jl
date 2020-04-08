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
function compute_many(msg::BitArray, key::BitArray)
    @assert size(key) == size(key)
    println("Key size : ", size(key, 2))
    println("Msg size : ", size(msg))

    intermediate_values = Dict{String, BitArray}()
    intermediate_values["SUB_KEY"] = BitArray{3}(undef, 48, size(key, 2), 16)
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
    # round 1
    
    # round 2
    # round 3
    # round 4
    # round 5 
    # round 6
    # round 7
    # round 8
    # round 9 
    # round 10
    # round 11
    # round 12
    # round 13
    # round 14
    # round 15
    # round 16
    # end
    return intermediate_values
    
    
end