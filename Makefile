SOURCES := $(wildcard *.c src/**/*.c *.cpp src/**/*.cpp)
OBJECTS := $(SOURCES:.c=.o)
OBJECTS := $(OBJECTS:.cpp=.o)
HEADERS := $(wildcard *.h include/*.h)

COMMON   := -O2 -Wall -Wformat=2 -Wno-format-nonliteral -march=native -DNDEBUG
CFLAGS   := $(CFLAGS) $(COMMON)
CXXFLAGS := $(CXXFLAGS) $(COMMON)
CC       := gcc
CXX      := g++
LD       := $(CC)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
GMP_CFLAGS := $(shell pkg-config --cflags gmp 2>/dev/null)
GMP_LIBS := $(shell pkg-config --libs gmp 2>/dev/null)

ifeq ($(strip $(OPENSSL_CFLAGS)),)
OPENSSL_CFLAGS := -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include
endif
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -lcrypto
endif
ifeq ($(strip $(GMP_CFLAGS)),)
GMP_CFLAGS := -I/opt/homebrew/opt/gmp/include -I/usr/local/opt/gmp/include
endif
ifeq ($(strip $(GMP_LIBS)),)
GMP_LIBS := -L/opt/homebrew/opt/gmp/lib -L/usr/local/opt/gmp/lib -lgmp
endif

LDFLAGS  := $(LDFLAGS) # -L/path/to/libs/
LDADD    := -lpthread $(OPENSSL_LIBS) $(GMP_LIBS) $(shell pkg-config --libs gtk+-3.0)
INCLUDE  := $(shell pkg-config --cflags gtk+-3.0) $(OPENSSL_CFLAGS) $(GMP_CFLAGS)
DEFS     := # -DLINUX

TARGETS  := chat dh-example

IMPL := chat.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

.PHONY : all
all : $(TARGETS)

# {{{ for debugging
DBGFLAGS := -g3 -UNDEBUG -O0
debug : CFLAGS += $(DBGFLAGS)
debug : CXXFLAGS += $(DBGFLAGS)
debug : all
.PHONY : debug
# }}}

chat : $(IMPL) dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

dh-example : dh-example.o dh.o keys.o util.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGETS) $(OBJECTS)

# vim:ft=make:foldmethod=marker:foldmarker={{{,}}}
