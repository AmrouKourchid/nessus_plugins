#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214659);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2025-24085",
    "CVE-2025-24086",
    "CVE-2025-24087",
    "CVE-2025-24092",
    "CVE-2025-24094",
    "CVE-2025-24096",
    "CVE-2025-24099",
    "CVE-2025-24100",
    "CVE-2025-24101",
    "CVE-2025-24102",
    "CVE-2025-24103",
    "CVE-2025-24106",
    "CVE-2025-24107",
    "CVE-2025-24108",
    "CVE-2025-24109",
    "CVE-2025-24112",
    "CVE-2025-24113",
    "CVE-2025-24114",
    "CVE-2025-24115",
    "CVE-2025-24116",
    "CVE-2025-24117",
    "CVE-2025-24118",
    "CVE-2025-24120",
    "CVE-2025-24121",
    "CVE-2025-24122",
    "CVE-2025-24123",
    "CVE-2025-24124",
    "CVE-2025-24126",
    "CVE-2025-24127",
    "CVE-2025-24128",
    "CVE-2025-24129",
    "CVE-2025-24130",
    "CVE-2025-24131",
    "CVE-2025-24134",
    "CVE-2025-24135",
    "CVE-2025-24136",
    "CVE-2025-24137",
    "CVE-2025-24138",
    "CVE-2025-24139",
    "CVE-2025-24140",
    "CVE-2025-24143",
    "CVE-2025-24145",
    "CVE-2025-24146",
    "CVE-2025-24149",
    "CVE-2025-24150",
    "CVE-2025-24151",
    "CVE-2025-24152",
    "CVE-2025-24153",
    "CVE-2025-24154",
    "CVE-2025-24156",
    "CVE-2025-24158",
    "CVE-2025-24159",
    "CVE-2025-24160",
    "CVE-2025-24161",
    "CVE-2025-24162",
    "CVE-2025-24163",
    "CVE-2025-24169",
    "CVE-2025-24174",
    "CVE-2025-24176",
    "CVE-2025-24177",
    "CVE-2025-24179",
    "CVE-2025-24185"
  );
  script_xref(name:"APPLE-SA", value:"122068");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/19");
  script_xref(name:"IAVA", value:"2025-A-0068-S");

  script_name(english:"macOS 15.x < 15.3 Multiple Vulnerabilities (122068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.3. It is, therefore, affected by
multiple vulnerabilities:

  - An out-of-bounds write was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.7.3, macOS Sonoma 14.7.3, visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3. An attacker may
    be able to cause unexpected system termination or corrupt kernel memory. (CVE-2025-24154)

  - A privacy issue was addressed with improved handling of files. This issue is fixed in macOS Sequoia 15.3,
    Safari 18.3, iOS 18.3 and iPadOS 18.3. Copying a URL from Web Inspector may lead to command injection.
    (CVE-2025-24150)

  - A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3,
    iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able
    to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against
    versions of iOS before iOS 17.2. (CVE-2025-24085)

  - The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Ventura
    13.7.3, macOS Sonoma 14.7.3, visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3,
    tvOS 18.3. Processing an image may lead to a denial-of-service. (CVE-2025-24086)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Sequoia 15.3. An
    app may be able to access protected user data. (CVE-2025-24087)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/122068");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24150");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '15.3.0', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.3' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
