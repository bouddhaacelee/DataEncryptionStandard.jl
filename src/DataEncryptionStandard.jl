module DataEncryptionStandard
	
	include("utils.jl")


	include("permutations.jl")
	include("simple.jl")
	include("many.jl")
	
	export compute, compute_many, fromStringtoBits, randomUInt64toBits

end # module
