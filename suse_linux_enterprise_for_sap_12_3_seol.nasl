#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/10/08. Deprecated by suse_linux_enterprise_server_for_sap_12_3_seol.nasl.
##

include('compat.inc');

if (description)
{
  script_id(201368);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_name(english:"SUSE Linux Enterprise For SAP SEoL (12.3.x) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its version, SUSE Linux Enterprise For SAP is 12.3.x. It is, therefore, no longer maintained by its vendor
or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.

This plugin has been deprecated as it is a duplicate of suse_linux_enterprise_server_for_sap_12_3_seol.nasl.");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"seol_date", value:"2019/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:linux_enterprise_for_sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:sles_sap");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use suse_linux_enterprise_server_for_sap_12_3_seol.nasl instead.');
