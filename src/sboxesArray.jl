SBOX = BitArray([
    true , true , true , false,    
    false, false, false, false, 
    false, true , false, false, 
    true , true , true , true ,
    true , true , false, true ,    
    false, true , true , true , 
    false, false, false, true , 
    false, true , false, false,
    false, false, true , false,  
    true , true , true , false, 
    true , true , true , true , 
    false, false, true , false,
    true , false, true , true ,    
    true , true , false, true , 
    true , false, false, false, 
    false, false, false, true ,
    false, false, true , true ,    
    true , false, true , false,  
    true , false, true , false, 
    false, true , true , false,
    false, true , true , false,   
    true , true , false, false, 
    true , true , false, false, 
    true , false, true , true ,
    false, true , false, true ,   
    true , false, false, true , 
    true , false, false, true , 
    false, true , false, true ,
    false, false, false, false, 
    false, false, true , true , 
    false, true , true , true , 
    true , false, false, false,
    false, true , false, false,  
    true , true , true , true , 
    false, false, false, true , 
    true , true , false, false,
    true , true , true , false,    
    true , false, false, false, 
    true , false, false, false, 
    false, false, true , false,
    true , true , false, true ,
    false, true , false, false, 
    false, true , true , false, 
    true , false, false, true ,
    false, false, true , false,  
    false, false, false, true , 
    true , false, true , true , 
    false, true , true , true ,
    true , true , true , true , 
    false, true , false, true , 
    true , true , false, false, 
    true , false, true , true ,
    true , false, false, true , 
    false, false, true , true , 
    false, true , true , true , 
    true , true , true , false,
    false, false, true , true , 
    true , false, true , false, 
    true , false, true , false, 
    false, false, false, false,
    false, true , false, true , 
    false, true , true , false, 
    false, false, false, false, 
    true , true , false, true])
const ARRAY_SBOX_1 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    true , true , true , true ,
    false, false, true , true ,
    false, false, false, true ,
    true , true , false, true ,
    true , false, false, false,
    false, true , false, false,
    true , true , true , false,
    false, true , true , true ,
    false, true , true , false,
    true , true , true , true ,
    true , false, true , true ,
    false, false, true , false,
    false, false, true , true ,
    true , false, false, false,
    false, true , false, false,
    true , true , true , false,
    true , false, false, true ,
    true , true , false, false, 
    false, true , true , true , 
    false, false, false, false,
    false, false, true , false, 
    false, false, false, true , 
    true , true , false, true , 
    true , false, true , false,
    true , true , false, false, 
    false, true , true , false, 
    false, false, false, false, 
    true , false, false, true ,
    false, true , false, true , 
    true , false, true , true , 
    true , false, true , false, 
    false, true , false, true ,
    false, false, false, false, 
    true , true , false, true , 
    true , true , true , false, 
    true , false, false, false,
    false, true , true , true , 
    true , false, true , false, 
    true , false, true , true , 
    false, false, false, true ,
    true , false, true , false, 
    false, false, true , true , 
    false, true , false, false, 
    true , true , true , true ,
    true , true , false, true , 
    false, true , false, false, 
    false, false, false, true , 
    false, false, true , false,
    false, true , false, true , 
    true , false, true , true , 
    true , false, false, false, 
    false, true , true , false,
    true , true , false, false, 
    false, true , true , true , 
    false, true , true , false, 
    true , true , false, false,
    true , false, false, true , 
    false, false, false, false, 
    false, false, true , true , 
    false, true , false, true ,
    false, false, true , false, 
    true , true , true , false, 
    true , true , true , true , 
    true , false, false, true])
    
const ARRAY_SBOX_2 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    true , false, true , false, 
    true , true , false, true , 
    false, false, false, false, 
    false, true , true , true ,
    true , false, false, true , 
    false, false, false, false, 
    true , true , true , false, 
    true , false, false, true ,
    false, true , true , false, 
    false, false, true , true , 
    false, false, true , true , 
    false, true , false, false,
    true , true , true , true , 
    false, true , true , false, 
    false, true , false, true , 
    true , false, true , false,
    false, false, false, true , 
    false, false, true , false, 
    true , true , false, true , 
    true , false, false, false,
    true , true , false, false, 
    false, true , false, true , 
    false, true , true , true , 
    true , true , true , false,
    true , false, true , true , 
    true , true , false, false, 
    false, true , false, false, 
    true , false, true , true ,
    false, false, true , false, 
    true , true , true , true , 
    true , false, false, false, 
    false, false, false, true ,
    true , true , false, true , 
    false, false, false, true , 
    false, true , true , false, 
    true , false, true , false,
    false, true , false, false, 
    true , true , false, true , 
    true , false, false, true , 
    false, false, false, false,
    true , false, false, false, 
    false, true , true , false, 
    true , true , true , true , 
    true , false, false, true ,
    false, false, true , true , 
    true , false, false, false, 
    false, false, false, false, 
    false, true , true , true ,
    true , false, true , true , 
    false, true , false, false, 
    false, false, false, true , 
    true , true , true , true ,
    false, false, true , false, 
    true , true , true , false, 
    true , true , false, false, 
    false, false, true , true ,
    false, true , false, true , 
    true , false, true , true , 
    true , false, true , false, 
    false, true , false, true ,
    true , true , true , false, 
    false, false, true , false, 
    false, true , true , true , 
    true , true , false, false])

const ARRAY_SBOX_3 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    false, true , true , true , 
    true , true , false, true , 
    true , true , false, true , 
    true , false, false, false,
    true , true , true , false, 
    true , false, true , true , 
    false, false, true , true , 
    false, true , false, true ,
    false, false, false, false, 
    false, true , true , false, 
    false, true , true , false, 
    true , true , true , true ,
    true , false, false, true , 
    false, false, false, false, 
    true , false, true , false, 
    false, false, true , true ,
    false, false, false, true , 
    false, true , false, false, 
    false, false, true , false, 
    false, true , true , true ,
    true , false, false, false, 
    false, false, true , false, 
    false, true , false, true , 
    true , true , false, false,
    true , false, true , true , 
    false, false, false, true , 
    true , true , false, false, 
    true , false, true , false,
    false, true , false, false, 
    true , true , true , false, 
    true , true , true , true , 
    true , false, false, true ,
    true , false, true , false, 
    false, false, true , true , 
    false, true , true , false, 
    true , true , true , true ,
    true , false, false, true , 
    false, false, false, false, 
    false, false, false, false, 
    false, true , true , false,
    true , true , false, false, 
    true , false, true , false, 
    true , false, true , true , 
    false, false, false, true ,
    false, true , true , true , 
    true , true , false, true , 
    true , true , false, true , 
    true , false, false, false,
    true , true , true , true , 
    true , false, false, true , 
    false, false, false, true , 
    false, true , false, false,
    false, false, true , true , 
    false, true , false, true , 
    true , true , true , false, 
    true , false, true , true ,
    false, true , false, true , 
    true , true , false, false, 
    false, false, true , false, 
    false, true , true , true ,
    true , false, false, false, 
    false, false, true , false, 
    false, true , false, false, 
    true , true , true , false])

const ARRAY_SBOX_4 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    false, false, true , false, 
    true , true , true , false, 
    true , true , false, false, 
    true , false, true , true ,
    false, true , false, false, 
    false, false, true , false, 
    false, false, false, true , 
    true , true , false, false,
    false, true , true , true , 
    false, true , false, false, 
    true , false, true , false, 
    false, true , true , true ,
    true , false, true , true , 
    true , true , false, true , 
    false, true , true , false, 
    false, false, false, true ,
    true , false, false, false, 
    false, true , false, true , 
    false, true , false, true , 
    false, false, false, false,
    false, false, true , true , 
    true , true , true , true , 
    true , true , true , true , 
    true , false, true , false,
    true , true , false, true , 
    false, false, true , true , 
    false, false, false, false, 
    true , false, false, true ,
    true , true , true , false, 
    true , false, false, false, 
    true , false, false, true , 
    false, true , true , false,
    false, true , false, false, 
    true , false, true , true , 
    false, false, true , false, 
    true , false, false, false,
    false, false, false, true , 
    true , true , false, false, 
    true , false, true , true , 
    false, true , true , true ,
    true , false, true , false, 
    false, false, false, true , 
    true , true , false, true , 
    true , true , true , false,
    false, true , true , true , 
    false, false, true , false, 
    true , false, false, false, 
    true , true , false, true ,
    true , true , true , true , 
    false, true , true , false, 
    true , false, false, true , 
    true , true , true , true ,
    true , true , false, false, 
    false, false, false, false, 
    false, true , false, true , 
    true , false, false, true ,
    false, true , true , false, 
    true , false, true , false, 
    false, false, true , true , 
    false, true , false, false,
    false, false, false, false, 
    false, true , false, true , 
    true , true , true , false, 
    false, false, true , true])
    
const ARRAY_SBOX_5 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    true , true , false, false, 
    true , false, true , false, 
    false, false, false, true , 
    true , true , true , true ,
    true , false, true , false, 
    false, true , false, false, 
    true , true , true , true , 
    false, false, true , false,
    true , false, false, true , 
    false, true , true , true , 
    false, false, true , false, 
    true , true , false, false,
    false, true , true , false, 
    true , false, false, true , 
    true , false, false, false, 
    false, true , false, true ,
    false, false, false, false, 
    false, true , true , false, 
    true , true , false, true , 
    false, false, false, true ,
    false, false, true , true , 
    true , true , false, true , 
    false, true , false, false, 
    true , true , true , false,
    true , true , true , false, 
    false, false, false, false, 
    false, true , true , true , 
    true , false, true , true ,
    false, true , false, true , 
    false, false, true , true , 
    true , false, true , true , 
    true , false, false, false,
    true , false, false, true , 
    false, true , false, false, 
    true , true , true , false, 
    false, false, true , true ,
    true , true , true , true , 
    false, false, true , false, 
    false, true , false, true , 
    true , true , false, false,
    false, false, true , false, 
    true , false, false, true , 
    true , false, false, false, 
    false, true , false, true ,
    true , true , false, false, 
    true , true , true , true , 
    false, false, true , true , 
    true , false, true , false,
    false, true , true , true , 
    true , false, true , true , 
    false, false, false, false, 
    true , true , true , false,
    false, true , false, false, 
    false, false, false, true , 
    true , false, true , false, 
    false, true , true , true ,
    false, false, false, true , 
    false, true , true , false, 
    true , true , false, true , 
    false, false, false, false,
    true , false, true , true , 
    true , false, false, false, 
    false, true , true , false, 
    true , true , false, true])

const ARRAY_SBOX_6 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    false, true , false, false, 
    true , true , false, true , 
    true , false, true , true , 
    false, false, false, false,
    false, false, true , false, 
    true , false, true , true , 
    true , true , true , false, 
    false, true , true , true ,
    true , true , true , true , 
    false, true , false, false, 
    false, false, false, false, 
    true , false, false, true ,
    true , false, false, false, 
    false, false, false, true , 
    true , true , false, true , 
    true , false, true , false,
    false, false, true , true , 
    true , true , true , false, 
    true , true , false, false, 
    false, false, true , true ,
    true , false, false, true , 
    false, true , false, true , 
    false, true , true , true , 
    true , true , false, false,
    false, true , false, true , 
    false, false, true , false, 
    true , false, true , false, 
    true , true , true , true ,
    false, true , true , false, 
    true , false, false, false, 
    false, false, false, true , 
    false, true , true , false,
    false, false, false, true , 
    false, true , true , false, 
    false, true , false, false, 
    true , false, true , true ,
    true , false, true , true , 
    true , true , false, true , 
    true , true , false, true , 
    true , false, false, false,
    true , true , false, false, 
    false, false, false, true , 
    false, false, true , true , 
    false, true , false, false,
    false, true , true , true , 
    true , false, true , false, 
    true , true , true , false, 
    false, true , true , true ,
    true , false, true , false, 
    true , false, false, true , 
    true , true , true , true , 
    false, true , false, true ,
    false, true , true , false, 
    false, false, false, false, 
    true , false, false, false, 
    true , true , true , true ,
    false, false, false, false, 
    true , true , true , false, 
    false, true , false, true , 
    false, false, true , false,
    true , false, false, true , 
    false, false, true , true , 
    false, false, true , false, 
    true , true , false, false])

const ARRAY_SBOX_7 = reshape(SBOX, 4, 64)

SBOX = BitArray([
    true , true , false, true , 
    false, false, false, true , 
    false, false, true , false, 
    true , true , true , true ,
    true , false, false, false, 
    true , true , false, true , 
    false, true , false, false, 
    true , false, false, false,
    false, true , true , false, 
    true , false, true , false, 
    true , true , true , true , 
    false, false, true , true ,
    true , false, true , true , 
    false, true , true , true , 
    false, false, false, true , 
    false, true , false, false,
    true , false, true , false, 
    true , true , false, false, 
    true , false, false, true , 
    false, true , false, true ,
    false, false, true , true , 
    false, true , true , false, 
    true , true , true , false, 
    true , false, true , true ,
    false, true , false, true , 
    false, false, false, false, 
    false, false, false, false, 
    true , true , true , false,
    true , true , false, false, 
    true , false, false, true , 
    false, true , true , true , 
    false, false, true , false,
    false, true , true , true , 
    false, false, true , false, 
    true , false, true , true , 
    false, false, false, true ,
    false, true , false, false, 
    true , true , true , false, 
    false, false, false, true , 
    false, true , true , true ,
    true , false, false, true , 
    false, true , false, false, 
    true , true , false, false, 
    true , false, true , false,
    true , true , true , false, 
    true , false, false, false, 
    false, false, true , false, 
    true , true , false, true ,
    false, false, false, false, 
    true , true , true , true , 
    false, true , true , false, 
    true , true , false, false,
    true , false, true , false, 
    true , false, false, true , 
    true , true , false, true , 
    false, false, false, false,
    true , true , true , true , 
    false, false, true , true , 
    false, false, true , true , 
    false, true , false, true ,
    false, true , false, true , 
    false, true , true , false, 
    true , false, false, false, 
    true , false, true , true])
    
const ARRAY_SBOX_8 = reshape(SBOX, 4, 64)