#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210361);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-10826", "CVE-2024-10827");
  script_xref(name:"IAVA", value:"2024-A-0706-S");

  script_name(english:"Google Chrome < 130.0.6723.116 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 130.0.6723.116. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2024_11_stable-channel-update-for-desktop advisory.

  - Use after free in Family Experiences. (CVE-2024-10826)

  - Use after free in Serial. (CVE-2024-10827)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d599fc9");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/370217726");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/375065084");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 130.0.6723.116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

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

google_chrome_check_version(fix:'130.0.6723.116', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
