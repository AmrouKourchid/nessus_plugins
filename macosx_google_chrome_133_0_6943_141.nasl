#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");
  script_xref(name:"IAVA", value:"2025-A-0121-S");

  script_name(english:"Google Chrome < 133.0.6943.141 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 133.0.6943.141. It is, therefore, affected
by a vulnerability as referenced in the 2025_02_stable-channel-update-for-desktop_25 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a56768a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 133.0.6943.141 or later.");
  script_set_attribute(attribute:"risk_factor", value:"Critical");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'133.0.6943.141', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
