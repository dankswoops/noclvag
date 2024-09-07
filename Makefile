#
# noclvag, Nostr OpenCL Vanity Address Generator.
# Copyright (C) 2024 alex0jsan <nostr:npub1alex0jsan7wt5aq7exv9je9qlvdwm69sr7u6m8msjr77xv6yj60qkp8462>
#
# noclvag is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# noclvag is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with noclvag.  If not, see <http://www.gnu.org/licenses/>.
#

LIBS=-lcrypto -lm -lpthread -lOpenCL
CFLAGS=-std=gnu2x -ggdb -O3 -Wall -Wno-deprecated-declarations -Wno-format -Wmissing-declarations -Wmissing-prototypes -Wshadow -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wundef -Wunused-macros -Walloc-zero -Wduplicated-branches -Wduplicated-cond -Winit-self -Wlogical-op

OBJS=noclvag-search.o noclvag-tool.o oclengine.o pattern.o util.o util-openssl.o
PROGS=noclvag-search noclvag-tool

all: $(PROGS)

noclvag-search: noclvag-search.o oclengine.o pattern.o util.o util-openssl.o
	$(CC) $^ -o $@ $(CFLAGS) -lcrypto -lsecp256k1 -lm -lpthread -lOpenCL

noclvag-tool: noclvag-tool.o util.o
	$(CC) $^ -o $@ $(CFLAGS) -lsecp256k1

clean:
	rm -f $(OBJS) $(PROGS) *.oclbin
