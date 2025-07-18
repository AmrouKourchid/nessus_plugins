#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157242);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2021-30960",
    "CVE-2021-30972",
    "CVE-2022-22579",
    "CVE-2022-22583",
    "CVE-2022-22585",
    "CVE-2022-22587",
    "CVE-2022-22593"
  );
  script_xref(name:"APPLE-SA", value:"HT213055");
  script_xref(name:"IAVA", value:"2022-A-0051-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/11");

  script_name(english:"macOS 11.x < 11.6.3 Multiple Vulnerabilities (HT213055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.3 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

  - A memory corruption issue in IOMobileFrameBuffer that can lead to arbitrary code execution with kernel
    privileges due to improper input validation. (CVE-2022-22587)

  - A buffer overflow issue in the kernel that can lead to arbitrary code execution with kernel privileges
    due to improper memory handling. (CVE-2022-22593)

  - An information disclosure issue in Model I/O that can lead to unexpected application termination or
    arbitrary code execution due to improper state management. (CVE-2022-22579)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22587");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '11.6.3', 'fixed_display' : 'macOS Big Sur 11.6.3' }];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
