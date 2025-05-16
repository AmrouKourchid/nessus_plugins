#TRUSTED 11e4fe35a68c8482f130060330d650d40202bccabbcfe3730eb7935415555380e2ceb46a9d045084d99428b918dcc44f4ac199af21c77fd9556e8b78121dea0c16ebba65a5b736e8ae01b90fdab1109ef9d78d74a8ad4b619db1c6229732993243f3dee554695a5519bdfa633ebf58e4103be7684c0670ebe0b022a0534b0f73789c7f735ac9477d0be5c1f5bcc8553e054f900a56a006745f52a6a724e53506269ba0299187db42e3537b3131fc92053a999f4928d74afa4ad82ef050bc833e7026eb6f5e5a41a82dfc107ad5b94c7e5f4df58a139b1a310feccd6a4a0a4b0646a72e11729c68965b23b0f379502310d71cad40f21fb45f7ef24d09dfbd9fd9a5d5527f09ef7730da20c681dd17668221369a5d53c15a13be09c6898f2646e77c25b66623657006a4857330f090fa9b8447f1982853df2f7e2f996b4ac72d4f69fe203cc4b48207e7824ad267d66f39dc102fb65820a6646a87f76258830e14bd5e7214427f03b464732efb1815f02c7e29f105b55e46088e0bd52f4d0874eb6e6693aa140f67aa3d7b37cfeff53b89c153d12d005abe66f897090baa141650fe07c884cb5b5a53a982b424157c273b123569b1eb31e2da2fd2bde2308071e4d109ebd2d220c1553bdd742d058a54b838cc11d21a1724dab4a9f215b6d2f9f35a23a176604498b9426fa5c8c06532d130d706ad5932832d80a5d9ff0d66086e
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 0.1
#
# <at:var at:name="NOGPL" />
###

include('patch_globals.inc');

namespace patch {
  ##
  # Population of global array vars defining supersedence comparison
  # logic methods. Global vars are declared in patch_globals.inc.
  #
  # If a method needs to be removed, replace the text name of the
  # method with empty string "" and leave all other settings intact.
  # Add a comment noting what the value was and when/why it was removed.
  # For example:
  #   #LOGIC_METHODS[FOO_COMP] = "Foo Comparison"
  #   LOGIC_METHODS[FOO_COMP] = ""; # Obsolete, see RES-999999
  ##
  LOGIC_METHODS[VER_COMP] = "Version comparison";
  LOGIC_OBJECTS[VER_COMP] = "patch::logic_ver_comp"; # patch_logic_ver_comp.inc

  LOGIC_METHODS[RPM_COMP] = "RPM comparison";
  LOGIC_OBJECTS[RPM_COMP] = "patch::logic_rpm_cmp"; # patch_logic_rpm_cmp.inc

  ##
  # Population of global array vars defining product families and
  # their default logic methods. Global vars are declared in
  # patch_globals.inc.
  #
  # If a family needs to be removed, replace the text name of the
  # family with empty string "" and leave all other settings intact.
  # Add a comment noting what the value was and when/why it was removed.
  # For example:
  #   #PROD_FAMILIES[FAM_FOO_BAR] = "Foosiful Bartrada";
  #   PROD_FAMILIES[FAM_FOO_BAR] = ""; # Obsolete, see RES-123456
  #
  # Naming conventions:
  #   - Global variable names should start with FAM_ and abbreviations
  #     used for the rest of the name should be short but legible
  #   - Friendly names are used for output and should include the
  #     vendor and product, be *spelled correctly*, and should
  #     represent a common sense grouping of products such as:
  #     - "Mozilla Products" which includes Firefox and Firefox ESR
  #     - "VMware vCenter" which includes vCenter 5.5.x, vCenter
  #       6.0.x, vCenter 6.5.x, etc
  #     - "Microsoft Office" which includes Office 2007, Office 2010,
  #       Office 2016 C2R, Office 2013 Enterprise, etc
  ##
  PROD_FAMILIES[FAM_MOZILLA] = "Mozilla Products";
  PROD_FAMILIES_LOGIC[FAM_MOZILLA] = VER_COMP;

  PROD_FAMILIES[FAM_RPM] = "RPM Packages";
  PROD_FAMILIES_LOGIC[FAM_RPM] = RPM_COMP;
}
