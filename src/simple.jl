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
function compute(msg::BitArray, key::BitArray)
    SBOX_OUT = BitArray(undef, 32, 1)
    # round 1
    R_1 = msg[IPbits_R]
    a = Cast_SBOX_IN(R_1[EXP] .⊻ key[SUB_KEY_1_P] )
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]

    # round 2
    R_2 = SBOX_OUT[P] .⊻ msg[IPbits_L]
    a = Cast_SBOX_IN(R_2[EXP] .⊻ key[SUB_KEY_2_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]

    # round 3
    R_3 = SBOX_OUT[P] .⊻ R_1
    a = Cast_SBOX_IN(R_3[EXP] .⊻ key[SUB_KEY_3_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]

    # round 4
    R_4 = SBOX_OUT[P] .⊻ R_2
    a = Cast_SBOX_IN(R_4[EXP] .⊻ key[SUB_KEY_4_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]

    # round 5
    R_5 = SBOX_OUT[P] .⊻ R_3
    a = Cast_SBOX_IN(R_5[EXP] .⊻ key[SUB_KEY_5_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 6
    R_6 = SBOX_OUT[P] .⊻ R_4
    a = Cast_SBOX_IN(R_6[EXP] .⊻ key[SUB_KEY_6_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 7
    R_7 = SBOX_OUT[P] .⊻ R_5
    a = Cast_SBOX_IN(R_7[EXP] .⊻ key[SUB_KEY_7_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 8
    R_8 = SBOX_OUT[P] .⊻ R_6
    a = Cast_SBOX_IN(R_8[EXP] .⊻ key[SUB_KEY_8_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 9
    R_9 = SBOX_OUT[P] .⊻ R_7
    a = Cast_SBOX_IN(R_9[EXP] .⊻ key[SUB_KEY_9_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 10
    R_10 = SBOX_OUT[P] .⊻ R_8
    a = Cast_SBOX_IN(R_10[EXP] .⊻ key[SUB_KEY_10_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 11
    R_11 = SBOX_OUT[P] .⊻ R_9
    a = Cast_SBOX_IN(R_11[EXP] .⊻ key[SUB_KEY_11_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 12
    R_12 = SBOX_OUT[P] .⊻ R_10
    a = Cast_SBOX_IN(R_12[EXP] .⊻ key[SUB_KEY_12_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 13
    R_13 = SBOX_OUT[P] .⊻ R_11
    a = Cast_SBOX_IN(R_13[EXP] .⊻ key[SUB_KEY_13_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 14
    R_14 = SBOX_OUT[P] .⊻ R_12
    a = Cast_SBOX_IN(R_14[EXP] .⊻ key[SUB_KEY_14_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    
    # round 15
    R_15 = SBOX_OUT[P] .⊻ R_13
    a = Cast_SBOX_IN(R_15[EXP] .⊻ key[SUB_KEY_15_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    # round 16
    R_16 = SBOX_OUT[P] .⊻ R_14
    a = Cast_SBOX_IN(R_16[EXP] .⊻ key[SUB_KEY_16_P])
    SBOX_OUT[1:4] = SBOX_1[a[1]]
    SBOX_OUT[5:8] = SBOX_2[a[2]]
    SBOX_OUT[9:12] = SBOX_3[a[3]]
    SBOX_OUT[13:16] = SBOX_4[a[4]]
    SBOX_OUT[17:20] = SBOX_5[a[5]]
    SBOX_OUT[21:24] = SBOX_6[a[6]]
    SBOX_OUT[25:28] = SBOX_7[a[7]]
    SBOX_OUT[29:32] = SBOX_8[a[8]]
    IP_1 = BitArray(undef, 64, 1)
    IP_1[1:32] = SBOX_OUT[P] .⊻ R_15
    IP_1[33:64] = R_16 
    return IP_1[FP]

end