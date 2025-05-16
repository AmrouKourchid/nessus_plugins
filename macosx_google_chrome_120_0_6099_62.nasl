#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186599);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2023-6508",
    "CVE-2023-6509",
    "CVE-2023-6510",
    "CVE-2023-6511",
    "CVE-2023-6512"
  );
  script_xref(name:"IAVA", value:"2023-A-0669-S");

  script_name(english:"Google Chrome < 120.0.6099.62 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 120.0.6099.62. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_12_stable-channel-update-for-desktop advisory.

  - Use after free in Media Stream in Google Chrome prior to 120.0.6099.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6508)

  - Use after free in Side Panel Search in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: High) (CVE-2023-6509)

  - Use after free in Media Capture in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: Medium) (CVE-2023-6510)

  - Inappropriate implementation in Autofill in Google Chrome prior to 120.0.6099.62 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-6511)

  - Inappropriate implementation in Web Browser UI in Google Chrome prior to 120.0.6099.62 allowed a remote
    attacker to potentially spoof the contents of an iframe dialog context menu via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-6512)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d175be7");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1497984");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1494565");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1480152");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1478613");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1457702");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 120.0.6099.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'120.0.6099.62', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
