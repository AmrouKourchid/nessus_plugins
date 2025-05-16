#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197181);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/28");

  script_cve_id(
    "CVE-2024-4947",
    "CVE-2024-4948",
    "CVE-2024-4949",
    "CVE-2024-4950"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/10");
  script_xref(name:"IAVA", value:"2024-A-0278-S");

  script_name(english:"Google Chrome < 125.0.6422.60 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 125.0.6422.60. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2024_05_stable-channel-update-for-desktop_15 advisory.

  - Type Confusion in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-4947)

  - Use after free in Dawn in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4948)

  - Use after free in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2024-4949)

  - Inappropriate implementation in Downloads in Google Chrome prior to 125.0.6422.60 allowed a remote
    attacker who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML
    page. (Chromium security severity: Low) (CVE-2024-4950)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/05/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3df5e6e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/340221135");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/333414294");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/326607001");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40065403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 125.0.6422.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4947");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'125.0.6422.60', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
