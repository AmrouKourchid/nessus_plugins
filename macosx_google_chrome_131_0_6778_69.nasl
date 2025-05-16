#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210779);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/06");

  script_cve_id(
    "CVE-2024-11110",
    "CVE-2024-11111",
    "CVE-2024-11112",
    "CVE-2024-11113",
    "CVE-2024-11114",
    "CVE-2024-11115",
    "CVE-2024-11116",
    "CVE-2024-11117"
  );
  script_xref(name:"IAVA", value:"2024-A-0743-S");

  script_name(english:"Google Chrome < 131.0.6778.69 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 131.0.6778.69. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2024_11_stable-channel-update-for-desktop_12 advisory.

  - Inappropriate implementation in Blink. (CVE-2024-11110)

  - Inappropriate implementation in Autofill. (CVE-2024-11111)

  - Use after free in Media. (CVE-2024-11112)

  - Use after free in Accessibility. (CVE-2024-11113)

  - Inappropriate implementation in Views. (CVE-2024-11114)

  - Insufficient policy enforcement in Navigation. (CVE-2024-11115)

  - Inappropriate implementation in Paint. (CVE-2024-11116)

  - Inappropriate implementation in FileSystem. (CVE-2024-11117)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/11/stable-channel-update-for-desktop_12.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2596518d");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/373263969");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/360520331");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/354824998");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/360274917");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/370856871");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/371929521");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40942531");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/40062534");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 131.0.6778.69 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'131.0.6778.69', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
