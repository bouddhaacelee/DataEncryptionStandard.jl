module DataEncryptionStandard
	
	include("utils.jl")

    include("sboxes.jl")
	include("permutations.jl")
	include("simple.jl")
	
	export compute, fromStringtoBits, randomUInt64toBits

	

	

end # module
