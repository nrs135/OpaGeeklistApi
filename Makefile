#
#   Copyright © 2011, 2012 MLstate
#
#   This file is part of OPA.
#
#   OPA is free software: you can redistribute it and/or modify it under the
#   terms of the GNU Affero General Public License, version 3, as published by
#   the Free Software Foundation.
#
#   OPA is distributed in the hope that it will be useful, but WITHOUT ANY
#   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#   FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for
#   more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with OPA.  If not, see <http://www.gnu.org/licenses/>.
#
PACKNAME = geeklist.opx
SRC = src/geeklist.opa
FLAG =

all: $(PACKNAME)

exe: geeklist_test.exe
geeklist_test.exe: $(PACKNAME)
	opa geeklist_test.opa --build-dir $(BUILDDIR) -I $(BUILDDIR) $(OPAOPT)

clean:
	rm -rf $(PACKNAME).broken _build _tracks

########################################
# MAKEFILE VARIABLES
OPACOMPILER ?= opa
OPA = $(OPACOMPILER) $(FLAG) $(OPAOPT)
PWD ?= $(shell pwd)
BUILDDIR ?= $(PWD)/_build
export BUILDDIR
DEPENDS = $(SRC)

########################################
# MAIN PACKAGE BUILDING
$(PACKNAME) : $(BUILDDIR)/$(PACKNAME)

$(BUILDDIR)/$(PACKNAME) : $(DEPENDS)
	@echo "### Building package $(PACKNAME)"
	mkdir -p $(BUILDDIR)
	$(OPA) --autocompile $(SRC) --build-dir $(BUILDDIR) -I $(BUILDDIR) $(OPAOPT)
	@rm -rf $(BUILDDIR)/$(PACKNAME)
	@mv $(PACKNAME) $(BUILDDIR)/

