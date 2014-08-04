npf.so: npf.c
	clang -Wall -shared -o $(.TARGET) \
		-lm -llua -lnpf \
		$(.ALLSRC)
