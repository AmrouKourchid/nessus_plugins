#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213517);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/07");

  script_cve_id(
    "CVE-2023-4504",
    "CVE-2023-5841",
    "CVE-2024-23237",
    "CVE-2024-27795",
    "CVE-2024-27849",
    "CVE-2024-27858",
    "CVE-2024-27860",
    "CVE-2024-27861",
    "CVE-2024-27869",
    "CVE-2024-27875",
    "CVE-2024-27876",
    "CVE-2024-27880",
    "CVE-2024-39894",
    "CVE-2024-40770",
    "CVE-2024-40791",
    "CVE-2024-40792",
    "CVE-2024-40797",
    "CVE-2024-40801",
    "CVE-2024-40825",
    "CVE-2024-40826",
    "CVE-2024-40831",
    "CVE-2024-40837",
    "CVE-2024-40838",
    "CVE-2024-40841",
    "CVE-2024-40842",
    "CVE-2024-40843",
    "CVE-2024-40844",
    "CVE-2024-40845",
    "CVE-2024-40846",
    "CVE-2024-40847",
    "CVE-2024-40848",
    "CVE-2024-40850",
    "CVE-2024-40855",
    "CVE-2024-40856",
    "CVE-2024-40857",
    "CVE-2024-40859",
    "CVE-2024-40860",
    "CVE-2024-40861",
    "CVE-2024-40866",
    "CVE-2024-41957",
    "CVE-2024-44122",
    "CVE-2024-44123",
    "CVE-2024-44125",
    "CVE-2024-44126",
    "CVE-2024-44128",
    "CVE-2024-44129",
    "CVE-2024-44130",
    "CVE-2024-44131",
    "CVE-2024-44132",
    "CVE-2024-44133",
    "CVE-2024-44134",
    "CVE-2024-44135",
    "CVE-2024-44137",
    "CVE-2024-44144",
    "CVE-2024-44145",
    "CVE-2024-44146",
    "CVE-2024-44148",
    "CVE-2024-44149",
    "CVE-2024-44151",
    "CVE-2024-44152",
    "CVE-2024-44153",
    "CVE-2024-44154",
    "CVE-2024-44155",
    "CVE-2024-44158",
    "CVE-2024-44160",
    "CVE-2024-44161",
    "CVE-2024-44163",
    "CVE-2024-44164",
    "CVE-2024-44165",
    "CVE-2024-44166",
    "CVE-2024-44167",
    "CVE-2024-44168",
    "CVE-2024-44169",
    "CVE-2024-44170",
    "CVE-2024-44174",
    "CVE-2024-44175",
    "CVE-2024-44176",
    "CVE-2024-44177",
    "CVE-2024-44178",
    "CVE-2024-44181",
    "CVE-2024-44182",
    "CVE-2024-44183",
    "CVE-2024-44184",
    "CVE-2024-44186",
    "CVE-2024-44187",
    "CVE-2024-44188",
    "CVE-2024-44189",
    "CVE-2024-44190",
    "CVE-2024-44191",
    "CVE-2024-44198",
    "CVE-2024-44203",
    "CVE-2024-44208"
  );
  script_xref(name:"APPLE-SA", value:"121238");

  script_name(english:"macOS 15.x < 15.0 Multiple Vulnerabilities (121238)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to the full release of 15.0. It is,
therefore, affected by multiple vulnerabilities:

  - This issue was addressed with improved validation of file attributes. This issue is fixed in macOS Sequoia
    15. An app may be able to break out of its sandbox. (CVE-2024-44148)

  - Due to failure in validating the length provided by an attacker-crafted PPD PostScript document, CUPS and
    libppd are susceptible to a heap-based buffer overflow and possibly code execution. This issue has been
    fixed in CUPS version 2.4.7, released in September of 2023. (CVE-2023-4504)

  - Due to a failure in validating the number of scanline samples of a OpenEXR file containing deep scanline
    data, Academy Software Foundation OpenEX image parsing library version 3.2.1 and prior is susceptible to a
    heap-based buffer overflow vulnerability. This issue was resolved as of versions v3.2.2 and v3.1.12 of the
    affected library. (CVE-2023-5841)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sequoia 15. An app may
    be able to cause a denial-of-service. (CVE-2024-23237)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sequoia 15. A
    camera extension may be able to access the internet. (CVE-2024-27795)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121238");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the full release of macOS 15.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var vuln_builds = [
  '24A5264n',
  '24A5279h',
  '24A5289g',
  '24A5289h',
  '24A5298h',
  '24A5309e',
  '24A5320a',
  '24A5327a',
  '24A5331b'
];

var matching_build = FALSE;

foreach var vuln_build (vuln_builds)
{
  if (tolower(vuln_build) == tolower(app_info.build))
  {
    matching_build = TRUE;
    break;
  }
}

if (!matching_build)
  audit(AUDIT_HOST_NOT, 'running a vulnerable build of macOS Sequoia 15.0');

# Ensure the output properly shows that the host is running a Beta version of macOS 15.
app_info.display_version = app_info.version + ' Build ' + app_info.build + ' (Beta Release)';

var constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.0.1', 'fixed_display' : 'macOS Sequoia 15.0 (Full Release)' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
