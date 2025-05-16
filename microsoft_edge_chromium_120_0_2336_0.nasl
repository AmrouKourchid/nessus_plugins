#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
# 
# @DEPRECATED@
#
# Disabled on 2024/01/19. Deprecated by microsoft_edge_chromium_120_0_2210_133.nasl.
##

include('compat.inc');

if (description)
{
  script_id(187966);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/14");

  script_name(english:"Microsoft Edge (Chromium) < 120.0.2336.0 Multiple Vulnerabilities (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. Please use plugin ID 189188 instead.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#january-11-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3844aad0");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Please use plugin ID 189188 instead.');
