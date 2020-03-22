module DataEncryptionStandard
    
    include("sboxes.jl")
	include("permutations.jl")
    
	export compute, fromStringtoBits, randomUInt64toBits
	
	"""
	fromStringtoBits(s)
	
	convert a hexadecimal string to an Array{Bool, 1}
	# Arguments
	 * s: a string

	# Output
	 * value: type : Array{Bool, 1}

	# Examples
	```julia-repl
	julia> msg = fromStringtoBits("8787878787878787")
	```
	"""
	function fromStringtoBits(s)
		value_from_string = bitstring(parse(UInt64, s, base=16))
		return convert(Array{Bool}, split(value_from_string, "") .== "1")
	end

	"""
	randomUInt64toBits()
	
	generate a random Array{Bool, 1}

	#Output
	 * value: type : Array{Bool, 1}

	# Examples
	```julia-repl
	julia> msg = randomUInt64toBits()
	```
	"""
	function randomUInt64toBits()
		value = bitstring(rand(UInt64))
		return convert(Array{Bool}, split(value, "") .== "1")
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
	function compute(msg::Array{Bool,1}, key::Array{Bool,1})
        #initial permutation
        IP = msg[IPbits]
        # round 1
		L_1, R_1 = IP[1:32], IP[33:64]
		EXP_1 = R_1[EXP]
		SUB_KEY_1 = key[SUB_KEY_1_P]
		############################

		SBOX_IN_1 = EXP_1 .⊻ SUB_KEY_1
		SBOX_OUt_1 = [SBOX_1[SBOX_IN_1[1:6]]; SBOX_2[SBOX_IN_1[7:12]]; SBOX_3[SBOX_IN_1[13:18]]; SBOX_4[SBOX_IN_1[19:24]]; SBOX_5[SBOX_IN_1[25:30]]; SBOX_6[SBOX_IN_1[31:36]]; SBOX_7[SBOX_IN_1[37:42]]; SBOX_8[SBOX_IN_1[43:48]]]

		# round 2
		L_2 = R_1
		R_2 = SBOX_OUt_1[P] .⊻ L_1
		EXP_2 = R_2[EXP]
		SUB_KEY_2 = key[SUB_KEY_2_P]
		SBOX_IN_2 = EXP_2 .⊻ SUB_KEY_2
		SBOX_OUt_2 = [SBOX_1[SBOX_IN_2[1:6]]; SBOX_2[SBOX_IN_2[7:12]]; SBOX_3[SBOX_IN_2[13:18]]; SBOX_4[SBOX_IN_2[19:24]]; SBOX_5[SBOX_IN_2[25:30]]; SBOX_6[SBOX_IN_2[31:36]]; SBOX_7[SBOX_IN_2[37:42]]; SBOX_8[SBOX_IN_2[43:48]]]
		P_2 = SBOX_OUt_2[P]

		# round 3
		L_3 = R_2
		R_3 = P_2 .⊻ L_2
		EXP_3 = R_3[EXP]
		SUB_KEY_3 = key[SUB_KEY_3_P]
		SBOX_IN_3 = EXP_3 .⊻ SUB_KEY_3
		SBOX_OUt_3 = [SBOX_1[SBOX_IN_3[1:6]]; SBOX_2[SBOX_IN_3[7:12]]; SBOX_3[SBOX_IN_3[13:18]]; SBOX_4[SBOX_IN_3[19:24]]; SBOX_5[SBOX_IN_3[25:30]]; SBOX_6[SBOX_IN_3[31:36]]; SBOX_7[SBOX_IN_3[37:42]]; SBOX_8[SBOX_IN_3[43:48]]]
		P_3 = SBOX_OUt_3[P]

		# round 4
		L_4 = R_3
		R_4 = P_3 .⊻ L_3
		EXP_4 = R_4[EXP]
		SUB_KEY_4 = key[SUB_KEY_4_P]
		SBOX_IN_4 = EXP_4 .⊻ SUB_KEY_4
		SBOX_OUt_4 = [SBOX_1[SBOX_IN_4[1:6]]; SBOX_2[SBOX_IN_4[7:12]]; SBOX_3[SBOX_IN_4[13:18]]; SBOX_4[SBOX_IN_4[19:24]]; SBOX_5[SBOX_IN_4[25:30]]; SBOX_6[SBOX_IN_4[31:36]]; SBOX_7[SBOX_IN_4[37:42]]; SBOX_8[SBOX_IN_4[43:48]]]
		P_4 = SBOX_OUt_4[P]

		# round 5
		L_5 = R_4
		R_5 = P_4 .⊻ L_4
		EXP_5 = R_5[EXP]
		SUB_KEY_5 = key[SUB_KEY_5_P]
		SBOX_IN_5 = EXP_5 .⊻ SUB_KEY_5
		SBOX_OUt_5 = [SBOX_1[SBOX_IN_5[1:6]]; SBOX_2[SBOX_IN_5[7:12]]; SBOX_3[SBOX_IN_5[13:18]]; SBOX_4[SBOX_IN_5[19:24]]; SBOX_5[SBOX_IN_5[25:30]]; SBOX_6[SBOX_IN_5[31:36]]; SBOX_7[SBOX_IN_5[37:42]]; SBOX_8[SBOX_IN_5[43:48]]]
		P_5 = SBOX_OUt_5[P]
		
		# round 6
		L_6 = R_5
		R_6 = P_5 .⊻ L_5
		EXP_6 = R_6[EXP]
		SUB_KEY_6 = key[SUB_KEY_6_P]
		SBOX_IN_6 = EXP_6 .⊻ SUB_KEY_6
		SBOX_OUt_6 = [SBOX_1[SBOX_IN_6[1:6]]; SBOX_2[SBOX_IN_6[7:12]]; SBOX_3[SBOX_IN_6[13:18]]; SBOX_4[SBOX_IN_6[19:24]]; SBOX_5[SBOX_IN_6[25:30]]; SBOX_6[SBOX_IN_6[31:36]]; SBOX_7[SBOX_IN_6[37:42]]; SBOX_8[SBOX_IN_6[43:48]]]
		P_6 = SBOX_OUt_6[P]
		
		# round 7
		L_7 = R_6
		R_7 = P_6 .⊻ L_6
		EXP_7 = R_7[EXP]
		SUB_KEY_7 = key[SUB_KEY_7_P]
		SBOX_IN_7 = EXP_7 .⊻ SUB_KEY_7
		SBOX_OUt_7 = hcat(SBOX_1[SBOX_IN_7[1:6]], SBOX_2[SBOX_IN_7[7:12]], SBOX_3[SBOX_IN_7[13:18]], SBOX_4[SBOX_IN_7[19:24]], SBOX_5[SBOX_IN_7[25:30]], SBOX_6[SBOX_IN_7[31:36]], SBOX_7[SBOX_IN_7[37:42]], SBOX_8[SBOX_IN_7[43:48]])
		P_7 = SBOX_OUt_7[P]
		
		# round 8
		L_8 = R_7
		R_8 = P_7 .⊻ L_7
		EXP_8 = R_8[EXP]
		SUB_KEY_8 = key[SUB_KEY_8_P]
		SBOX_IN_8 = EXP_8 .⊻ SUB_KEY_8
		SBOX_OUt_8 = hcat(SBOX_1[SBOX_IN_8[1:6]], SBOX_2[SBOX_IN_8[7:12]], SBOX_3[SBOX_IN_8[13:18]], SBOX_4[SBOX_IN_8[19:24]], SBOX_5[SBOX_IN_8[25:30]], SBOX_6[SBOX_IN_8[31:36]], SBOX_7[SBOX_IN_8[37:42]], SBOX_8[SBOX_IN_8[43:48]])
		P_8 = SBOX_OUt_8[P]
		
		# round 9
		L_9 = R_8
		R_9 = P_8 .⊻ L_8
		EXP_9 = R_9[EXP]
		SUB_KEY_9 = key[SUB_KEY_9_P]
		SBOX_IN_9 = EXP_9 .⊻ SUB_KEY_9
		SBOX_OUt_9 = hcat(SBOX_1[SBOX_IN_9[1:6]], SBOX_2[SBOX_IN_9[7:12]], SBOX_3[SBOX_IN_9[13:18]], SBOX_4[SBOX_IN_9[19:24]], SBOX_5[SBOX_IN_9[25:30]], SBOX_6[SBOX_IN_9[31:36]], SBOX_7[SBOX_IN_9[37:42]], SBOX_8[SBOX_IN_9[43:48]])
		P_9 = SBOX_OUt_9[P]
		
		# round 10
		L_10 = R_9
		R_10 = P_9 .⊻ L_9
		EXP_10 = R_10[EXP]
		SUB_KEY_10 = key[SUB_KEY_10_P]
		SBOX_IN_10 = EXP_10 .⊻ SUB_KEY_10
		SBOX_OUt_10 = hcat(SBOX_1[SBOX_IN_10[1:6]], SBOX_2[SBOX_IN_10[7:12]], SBOX_3[SBOX_IN_10[13:18]], SBOX_4[SBOX_IN_10[19:24]], SBOX_5[SBOX_IN_10[25:30]], SBOX_6[SBOX_IN_10[31:36]], SBOX_7[SBOX_IN_10[37:42]], SBOX_8[SBOX_IN_10[43:48]])
		P_10 = SBOX_OUt_10[P]
		
		# round 11
		L_11 = R_10
		R_11 = P_10 .⊻ L_10
		EXP_11 = R_11[EXP]
		SUB_KEY_11 = key[SUB_KEY_11_P]
		SBOX_IN_11 = EXP_11 .⊻ SUB_KEY_11
		SBOX_OUt_11 = hcat(SBOX_1[SBOX_IN_11[1:6]], SBOX_2[SBOX_IN_11[7:12]], SBOX_3[SBOX_IN_11[13:18]], SBOX_4[SBOX_IN_11[19:24]], SBOX_5[SBOX_IN_11[25:30]], SBOX_6[SBOX_IN_11[31:36]], SBOX_7[SBOX_IN_11[37:42]], SBOX_8[SBOX_IN_11[43:48]])
		P_11 = SBOX_OUt_11[P]
		
		# round 12
		L_12 = R_11
		R_12 = P_11 .⊻ L_11
		EXP_12 = R_12[EXP]
		SUB_KEY_12 = key[SUB_KEY_12_P]
		SBOX_IN_12 = EXP_12 .⊻ SUB_KEY_12
		SBOX_OUt_12 = hcat(SBOX_1[SBOX_IN_12[1:6]], SBOX_2[SBOX_IN_12[7:12]], SBOX_3[SBOX_IN_12[13:18]], SBOX_4[SBOX_IN_12[19:24]], SBOX_5[SBOX_IN_12[25:30]], SBOX_6[SBOX_IN_12[31:36]], SBOX_7[SBOX_IN_12[37:42]], SBOX_8[SBOX_IN_12[43:48]])
		P_12 = SBOX_OUt_12[P]
		
		# round 13
		L_13 = R_12
		R_13 = P_12 .⊻ L_12
		EXP_13 = R_13[EXP]
		SUB_KEY_13 = key[SUB_KEY_13_P]
		SBOX_IN_13 = EXP_13 .⊻ SUB_KEY_13
		SBOX_OUt_13 = hcat(SBOX_1[SBOX_IN_13[1:6]], SBOX_2[SBOX_IN_13[7:12]], SBOX_3[SBOX_IN_13[13:18]], SBOX_4[SBOX_IN_13[19:24]], SBOX_5[SBOX_IN_13[25:30]], SBOX_6[SBOX_IN_13[31:36]], SBOX_7[SBOX_IN_13[37:42]], SBOX_8[SBOX_IN_13[43:48]])
		P_13 = SBOX_OUt_13[P]
		
		# round 14
		L_14 = R_13
		R_14 = P_13 .⊻ L_13
		EXP_14 = R_14[EXP]
		SUB_KEY_14 = key[SUB_KEY_14_P]
		SBOX_IN_14 = EXP_14 .⊻ SUB_KEY_14
		SBOX_OUt_14 = hcat(SBOX_1[SBOX_IN_14[1:6]], SBOX_2[SBOX_IN_14[7:12]], SBOX_3[SBOX_IN_14[13:18]], SBOX_4[SBOX_IN_14[19:24]], SBOX_5[SBOX_IN_14[25:30]], SBOX_6[SBOX_IN_14[31:36]], SBOX_7[SBOX_IN_14[37:42]], SBOX_8[SBOX_IN_14[43:48]])
		P_14 = SBOX_OUt_14[P]
		
		# round 15
		L_15 = R_14
		R_15 = P_14 .⊻ L_14
		EXP_15 = R_15[EXP]
		SUB_KEY_15 = key[SUB_KEY_15_P]
		SBOX_IN_15 = EXP_15 .⊻ SUB_KEY_15
		SBOX_OUt_15 = hcat(SBOX_1[SBOX_IN_15[1:6]], SBOX_2[SBOX_IN_15[7:12]], SBOX_3[SBOX_IN_15[13:18]], SBOX_4[SBOX_IN_15[19:24]], SBOX_5[SBOX_IN_15[25:30]], SBOX_6[SBOX_IN_15[31:36]], SBOX_7[SBOX_IN_15[37:42]], SBOX_8[SBOX_IN_15[43:48]])
		P_15 = SBOX_OUt_15[P]
		
		# round 16
		L_16 = R_15
		R_16 = P_15 .⊻ L_15
		EXP_16 = R_16[EXP]
		SUB_KEY_16 = key[SUB_KEY_16_P]
		SBOX_IN_16 = EXP_16 .⊻ SUB_KEY_16
		SBOX_OUt_16 = hcat(SBOX_1[SBOX_IN_16[1:6]], SBOX_2[SBOX_IN_16[7:12]], SBOX_3[SBOX_IN_16[13:18]], SBOX_4[SBOX_IN_16[19:24]], SBOX_5[SBOX_IN_16[25:30]], SBOX_6[SBOX_IN_16[31:36]], SBOX_7[SBOX_IN_16[37:42]], SBOX_8[SBOX_IN_16[43:48]])
		P_16 = SBOX_OUt_16[P]
		IP_1 = hcat(P_16 .⊻ L_16, R_16)
		OUT = IP_1[[40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]]
		return OUT
    end 

end # module
