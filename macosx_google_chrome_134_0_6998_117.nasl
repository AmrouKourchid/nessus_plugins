#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232981);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id("CVE-2025-2476");
  script_xref(name:"IAVA", value:"2025-A-0189-S");

  script_name(english:"Google Chrome < 134.0.6998.117 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 134.0.6998.117. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2025_03_stable-channel-update-for-desktop_19 advisory.

  - CVE-2025-2476 is a use after free in Lens. It was reported by SungKwon Lee of Enki Whitehat on 2025-03-05.
    (CVE-2025-2476)

  - Use after free in Lens in Google Chrome prior to 134.0.6998.117 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical) (CVE-2025-2476)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37954f14");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/401029609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 134.0.6998.117 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/20");

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
  fix:'134.0.6998.117',
  fixed_display:'134.0.6998.117 / 134.0.6998.118',
  severity:SECURITY_HOLE,
  xss:FALSE,
  xsrf:FALSE
  );
