#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# sasl.inc
# Revision: 1.3
#

include('byte_func.inc');
include('compat_shared.inc');

##
# Constructs a SASL plain text credentials payload.
# https://tools.ietf.org/html/rfc4616
# 
# param user Username.
# param pass Password.
# 
# return Raw string in SASL plain text format.
##
function sasl_plaintext(user, pass)
{
  var length = len(user) + len(pass) + 2;
  return raw_string(raw_int32(length), 0x00, user, 0x00, pass);
}
