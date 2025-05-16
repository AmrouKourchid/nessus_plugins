#TRUSTED 1bb855e9b890d5c81600f9a1cc2bef74106982a928b2168917628a7d1bab07922ba96914a48874ddd151b1cf2699897505aa6c33f53e0fdcd78205fcbc75e317db0027cf4fab11eb2a99ddbe5c041235a990c36d9737e3e338a6b51a7e3e062fef973ced8e18ea1f5b2c1a762b714bc5e8f0abcee3f355d8731d2d4167f10033fd09cb5c868ddd02a3dfb5e5a82d9b571ff6e243c57580a77f426d0ed47fd22e7059826befb08b4b2487dda412eb0c6a4469fe2f537f81c3031a5b6ed100a0a70fe777bb5c129f51eb4ef81d6a6d0f37515a8ce565b2676dbfa27fb608042e29c98c7619b358fd34aab813cf87115d49e28b17ca0791c15460325b1c4fb1bf987161b713ba52075e286447f316cce0dfbe17e7c1717c797c25dd40fa8b623960a44abb252e1df957fd5d8a30d2010dcf4598a00bdae432510a1b76c46993571db846d423633172fee56485715852fb847256281ae8ccadf45d76dab2f904d04a790362f16952088237488db58171d39d71ee11af7abd07218b64e4b266bcceb2d27be40d6ca1bb01990fd36d2146bbeaac1c9726d450bf1353975ffbb5f1aef9e9b0b6e670f866a57cc7a471c14a2120c8fc0f9f042b90d5145fe69181328ae389e70e17dcca013b70d40ef6db21cc25ef2ece65f6cadde88d51e5df79d46490801f89e98f56cb0b8eb0cb0f0ddf5ab3d8e9fced023c2ff1212c724622ede7dc
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# The globals included here are the bare minimum to enable the
# functionality of patch::log_finding() in patch_log.inc
#
# Revision: 0.2
#
# <at:var at:name="NOGPL" />
###

# Workaround for SCRIPT_NAME unpredictable behavior within namespaces
global_var THIS_SCRIPT = SCRIPT_NAME;

namespace patch {
  ##
  # Global vars defining supersedence comparison logic methods
  # For consistent compatibility, once assigned, these values should
  # not be changed.
  #
  # Naming convention:
  #   - Global variable names should end with _COMP and abbreviations
  #     used for the rest of the name should be short but legible
  ##
  global_var VER_COMP = 1;
  global_var RPM_COMP = 2;

  ##
  # Global vars defining product families
  # For consistent compatibility, once assigned, these values should
  # not be changed
  #
  # Naming convention:
  #   - Global variable names should start with FAM_ and abbreviations
  #     used for the rest of the name should be short but legible
  ##
  global_var FAM_MOZILLA  = 1;
  global_var FAM_RPM      = 2;

  ##
  # Global arrays that hold mappings of:
  # - Logic methods to their friendly names and logic object names
  # - Product families to their friendly names and logic methods
  #
  # These arrays are populated in patch_static.inc
  ##
  global_var LOGIC_METHODS = [];
  global_var LOGIC_OBJECTS = [];

  global_var PROD_FAMILIES = [];
  global_var PROD_FAMILIES_LOGIC = [];

  ##
  # Table names
  ##
  global_var _TBL_RAW_FINDINGS = "RawProductFindings"; # Scratchpad only

  ##
  # Globals for debugging
  ##
  global_var LOGNAME = 'patch_supersedence.log';
}
