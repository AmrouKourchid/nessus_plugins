#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.4
#
# This file is an include wrapper for the migration of the mongodb compliance .statics

include("byte_func.inc");
include("compat_shared.inc");
include("crypto_func.inc");
include("lists.inc");
include("math64.inc");
include("debug.inc");
include("spad_log_func.inc");
#pragma static(include)
include("compliance_forward_compat.static");
include("mongodb_bson.static");
include("mongodb_driver.static");
include("mongodb_functions.static");
#pragma static(include:false)

global_var _mongodb_library_in_use = "nessus-plugins";

