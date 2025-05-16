#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232535);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2025-1920",
    "CVE-2025-2135",
    "CVE-2025-2136",
    "CVE-2025-2137",
    "CVE-2025-24201"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/03");
  script_xref(name:"IAVA", value:"2025-A-0163-S");

  script_name(english:"Google Chrome < 134.0.6998.88 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 134.0.6998.88. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2025_03_stable-channel-update-for-desktop_10 advisory.

  - Out of bounds read in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to perform out
    of bounds memory access via a crafted HTML page. (Chromium security severity: Medium) (CVE-2025-2137)

  - Use after free in Inspector in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2025-2136)

  - Type Confusion in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2025-1920,
    CVE-2025-2135)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fec80b7c");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/398065918");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/400052777");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/401059730");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/395032416");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/398999390");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 134.0.6998.88 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2136");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-2137");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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

google_chrome_check_version(
  fix:'134.0.6998.88',
  fixed_display:'134.0.6998.88 / 134.0.6998.89',
  severity:SECURITY_HOLE,
  xss:FALSE,
  xsrf:FALSE
  );
