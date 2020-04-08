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
    return convert(BitArray, split(value_from_string, "") .== "1")
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
    return convert(BitArray, split(value, "") .== "1")
end

"""
TODO : for this, use macro or generated function
"""
function Cast_SBOX_IN(d::BitArray)
    array = [1, 1, 1, 1, 1, 1, 1, 1]
    
    ret::UInt64 = d[1]
    ret <<= 1
    ret |= d[2]
    ret <<= 1
    ret |= d[3]
    ret <<= 1
    ret |= d[4]
    ret <<= 1
    ret |= d[5]
    ret <<= 1
    ret |= d[6]
    array[1] += ret
    ret = d[7]
    ret <<= 1
    ret |= d[8]
    ret <<= 1
    ret |= d[9]
    ret <<= 1
    ret |= d[10]
    ret <<= 1
    ret |= d[11]
    ret <<= 1
    ret |= d[12]
    array[2] += ret 
    ret = d[13]
    ret <<= 1
    ret |= d[14]
    ret <<= 1
    ret |= d[15]
    ret <<= 1
    ret |= d[16]
    ret <<= 1
    ret |= d[17]
    ret <<= 1
    ret |= d[18]
    array[3] += ret
    ret = d[19]
    ret <<= 1
    ret |= d[20]
    ret <<= 1
    ret |= d[21]
    ret <<= 1
    ret |= d[22]
    ret <<= 1
    ret |= d[23]
    ret <<= 1
    ret |= d[24]
    array[4] += ret
    ret = d[25]
    ret <<= 1
    ret |= d[26]
    ret <<= 1
    ret |= d[27]
    ret <<= 1
    ret |= d[28]
    ret <<= 1
    ret |= d[29]
    ret <<= 1
    ret |= d[30]
    array[5] += ret
    ret = d[31]
    ret <<= 1
    ret |= d[32]
    ret <<= 1
    ret |= d[33]
    ret <<= 1
    ret |= d[34]
    ret <<= 1
    ret |= d[35]
    ret <<= 1
    ret |= d[36]
    array[6] += ret
    ret = d[37]
    ret <<= 1
    ret |= d[38]
    ret <<= 1
    ret |= d[39]
    ret <<= 1
    ret |= d[40]
    ret <<= 1
    ret |= d[41]
    ret <<= 1
    ret |= d[42]
    array[7] += ret
    ret = d[43]
    ret <<= 1
    ret |= d[44]
    ret <<= 1
    ret |= d[45]
    ret <<= 1
    ret |= d[46]
    ret <<= 1
    ret |= d[47]
    ret <<= 1
    ret |= d[48]
    array[8] += ret

    return array
end