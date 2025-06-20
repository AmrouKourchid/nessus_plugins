#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234957);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id(
    "CVE-2025-4050",
    "CVE-2025-4051",
    "CVE-2025-4052",
    "CVE-2025-4096"
  );
  script_xref(name:"IAVA", value:"2025-A-0303-S");

  script_name(english:"Google Chrome < 136.0.7103.48 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 136.0.7103.48. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2025_04_stable-channel-update-for-desktop_29 advisory.

  - Heap buffer overflow in HTML. (CVE-2025-4096)

  - Out of bounds memory access in DevTools. (CVE-2025-4050)

  - Insufficient data validation in DevTools. (CVE-2025-4051)

  - Inappropriate implementation in DevTools. (CVE-2025-4052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/04/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?448caec5");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/409911705");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/409342999");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/404000989");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/401927528");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 136.0.7103.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-4096");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-4050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/29");

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

google_chrome_check_version(fix:'136.0.7103.48', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
