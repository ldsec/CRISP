# This sample should be run after make libHEAAN.a file in lib folder

# All Target
all: clean MPCmult

# Tool invocations
MPCmult:
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ runMPCmult.cpp -o MPCmult -L/usr/local/lib ../lib/libHEAAN.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread -lcrypto
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	rm -rf MPCmult

run:
	./MPCmult