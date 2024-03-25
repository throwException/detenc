# the name of the target program
TARGET  = detenc

# other source files and the associated object files (this can be blank)
SRC_CC  = enc.cc
SRC_C   = 
OBJ     = $(SRC_CC:.cc=.o) $(SRC_C:.c=.o)

# special include directories
INCLUDE = -I.

# special libraries (none for now)
LIB     = -lcrypto

# select the compiler and flags
CCC      = g++
CCFLAGS  = 
CC       = gcc
CFLAGS   = 

.SUFFIXES: .cc .c

# specify how to compile the .c files
%.c.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

# specify how to compile the .cc files
%.cc.o: %.cc
	$(CCC) $(CCFLAGS) $(INCLUDE) -c $<

# if you type 'make' without arguments, this is the default
all: $(TARGET)

# specify how to compile the target
$(TARGET): $(OBJ) $(TARGET).cc
	$(CCC) $(CCFLAGS) $(INCLUDE) $(TARGET).cc $(OBJ) $(LIB) -o $(TARGET)

# remove binaries
clean:
	rm -f $(OBJ) $(TARGET).o $(TARGET)

# remove binaries and other junk
clobber:
	make clean
	rm -f core *~

# this will add the file dependencies below, i.e. it modifies this file
depend:
	makedepend -- $(CFLAGS) -- $(INCLUDE) -- $(SRC_C) $(TARGET).c
	makedepend -- $(CCFLAGS) -- $(INCLUDE) -- $(SRC_CC) $(TARGET).cc

