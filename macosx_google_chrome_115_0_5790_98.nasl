#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178446);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/07");

  script_cve_id(
    "CVE-2023-3727",
    "CVE-2023-3728",
    "CVE-2023-3730",
    "CVE-2023-3732",
    "CVE-2023-3733",
    "CVE-2023-3734",
    "CVE-2023-3735",
    "CVE-2023-3736",
    "CVE-2023-3737",
    "CVE-2023-3738",
    "CVE-2023-3740"
  );
  script_xref(name:"IAVA", value:"2023-A-0375-S");

  script_name(english:"Google Chrome < 115.0.5790.98 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 115.0.5790.98. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_07_stable-channel-update-for-desktop advisory.

  - Use after free in WebRTC. (CVE-2023-3727, CVE-2023-3728)

  - Use after free in Tab Groups. (CVE-2023-3730)

  - Out of bounds memory access in Mojo. (CVE-2023-3732)

  - Inappropriate implementation in WebApp Installs. (CVE-2023-3733)

  - Inappropriate implementation in Picture In Picture. (CVE-2023-3734)

  - Inappropriate implementation in Web API Permission Prompts. (CVE-2023-3735)

  - Inappropriate implementation in Custom Tabs. (CVE-2023-3736)

  - Inappropriate implementation in Notifications. (CVE-2023-3737)

  - Inappropriate implementation in Autofill. (CVE-2023-3738)

  - Insufficient validation of untrusted input in Themes. (CVE-2023-3740)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d784a729");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1454086");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1457421");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1453465");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450899");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450203");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450376");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1394410");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1434438");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1446754");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1434330");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1405223");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 115.0.5790.98 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3732");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'115.0.5790.98', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
