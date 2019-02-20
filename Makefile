PPGSS_DIR:=../PPGSS
PALISADE_DIR=$(PPGSS_DIR)/external-libraries/palisade-student-edition

CXX := /usr/local/opt/llvm/bin/clang++

PALISADE_SUB_DIRS := core pke trapdoor abe signature circuit wip

CFLAGS := -O3 -g
CFLAGS += -I$(PALISADE_DIR)/src
CFLAGS += -I$(PALISADE_DIR)/third-party/include
CFLAGS += $(patsubst %,-I$(PALISADE_DIR)/src/%/lib,$(PALISADE_SUB_DIRS))

LDFLAGS += -L/usr/local/opt/llvm/lib -Wl,-rpath,/usr/local/opt/llvm/lib
# LDFLAGS += -lgmp -lgmpxx -lcrypto
LDFLAGS += -L$(PALISADE_DIR)/bin/lib -L$(PALISADE_DIR)/third-party/lib
LDFLAGS += -dinamiclib -lPALISADEtrapdoor -lPALISADEwip -lPALISADEpke -lPALISADEcore


all: test_cc test_vec

clean:
	rm -rf bin/test_* *.dSYM

test_cc: test_cc.cpp
	$(CXX) $^ -o $@ $(CFLAGS) $(LDFLAGS)
	mv $@ bin/

test_vec: test_vec.cpp
	$(CXX) $^ -o $@ $(CFLAGS) $(LDFLAGS)
	mv $@ bin/
