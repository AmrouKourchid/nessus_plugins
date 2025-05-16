#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188160);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2024-0517", "CVE-2024-0518", "CVE-2024-0519");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/07");
  script_xref(name:"IAVA", value:"2024-A-0042-S");

  script_name(english:"Google Chrome < 120.0.6099.224 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 120.0.6099.224. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_01_stable-channel-update-for-desktop_16 advisory.

  - Out of bounds write in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0517)

  - Type confusion in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-0518)

  - Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0519)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/01/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88013c25");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1515930");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1507412");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1517354");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 120.0.6099.224 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0519");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

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

google_chrome_check_version(fix:'120.0.6099.224', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
