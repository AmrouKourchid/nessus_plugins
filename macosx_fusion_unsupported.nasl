##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024/03/20. Deprecated by VMWare Fusion Mac - SEoL
##

include("compat.inc");

if (description)
{
  script_id(55851);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_xref(name:"IAVA", value:"0001-A-0619");

  script_name(english:"VMware Fusion Unsupported Version Detection (deprecated)");
  script_summary(english:"Checks if a VMware Fusion version is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. For plugins which identify unsupported instances of this product, 
search the plugin feed for VMWare Fusion Mac - SEoL.");
  # http://www.vmware.com/support/policies/lifecycle/general/index.html#policy_fusion
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?785cb9aa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Fusion that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Fusion/Version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. For plugins which identify unsupported instances of this product, search the plugin feed for ManageEngine Applications Managers SEoL.');
