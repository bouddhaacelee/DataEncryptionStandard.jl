# Data Encryption Standard in Julia

The Data  Encryption  Standard  (DES)  is  a  symmetric-key  block  cipher  published  by  the  National Institute of Standards and Technology(NIST).

This code is a Julia package implementing this algorithm. 

## Features

This package provides three functions : 
* fromStringtoBits
* randomUInt64toBits
* compute

### fromStringtoBits(s)
Convert a hexadecimal string to an Array{Bool, 1}
#### Arguments
* s: a string
#### Output
* value: type : Array{Bool, 1}
#### Examples
julia> msg = fromStringtoBits("8787878787878787")

### randomUInt64toBits()
Generate a random Array{Bool, 1}
#### Output
* value: type : Array{Bool, 1}
#### Examples
julia> msg = randomUInt64toBits()

### compute(msg, key)
Compute the DES for msg with key. 
#### Arguments
* msg: the plaintext to encrypt, type : Array{Bool, 1}
* key: the key used for encryption, type : Array{Bool, 1} 
#### Output
* cipher: result of the DES, , type : Array{Bool, 1}
#### Examples
julia> msg = fromStringtoBits("8787878787878787")

julia> key = fromStringtoBits("0e329232ea6d0d73")

julia> out = compute(msg, key)

julia> out == fromStringtoBits("0000000000000000")

true

	
