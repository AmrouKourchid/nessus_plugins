#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207226);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2023-27952",
    "CVE-2023-38709",
    "CVE-2023-52356",
    "CVE-2023-6277",
    "CVE-2024-2004",
    "CVE-2024-2379",
    "CVE-2024-2398",
    "CVE-2024-2466",
    "CVE-2024-24795",
    "CVE-2024-27316",
    "CVE-2024-27862",
    "CVE-2024-27863",
    "CVE-2024-27871",
    "CVE-2024-27872",
    "CVE-2024-27873",
    "CVE-2024-27877",
    "CVE-2024-27878",
    "CVE-2024-27881",
    "CVE-2024-27882",
    "CVE-2024-27883",
    "CVE-2024-40774",
    "CVE-2024-40775",
    "CVE-2024-40776",
    "CVE-2024-40777",
    "CVE-2024-40778",
    "CVE-2024-40779",
    "CVE-2024-40780",
    "CVE-2024-40781",
    "CVE-2024-40782",
    "CVE-2024-40783",
    "CVE-2024-40784",
    "CVE-2024-40785",
    "CVE-2024-40787",
    "CVE-2024-40788",
    "CVE-2024-40789",
    "CVE-2024-40793",
    "CVE-2024-40794",
    "CVE-2024-40795",
    "CVE-2024-40796",
    "CVE-2024-40798",
    "CVE-2024-40799",
    "CVE-2024-40800",
    "CVE-2024-40802",
    "CVE-2024-40803",
    "CVE-2024-40804",
    "CVE-2024-40805",
    "CVE-2024-40806",
    "CVE-2024-40807",
    "CVE-2024-40809",
    "CVE-2024-40810",
    "CVE-2024-40811",
    "CVE-2024-40812",
    "CVE-2024-40814",
    "CVE-2024-40815",
    "CVE-2024-40816",
    "CVE-2024-40817",
    "CVE-2024-40818",
    "CVE-2024-40821",
    "CVE-2024-40822",
    "CVE-2024-40823",
    "CVE-2024-40824",
    "CVE-2024-40827",
    "CVE-2024-40828",
    "CVE-2024-40832",
    "CVE-2024-40833",
    "CVE-2024-40834",
    "CVE-2024-40835",
    "CVE-2024-40836",
    "CVE-2024-44141",
    "CVE-2024-44185",
    "CVE-2024-44199",
    "CVE-2024-44205",
    "CVE-2024-44206",
    "CVE-2024-44305",
    "CVE-2024-44306",
    "CVE-2024-44307",
    "CVE-2024-4558",
    "CVE-2024-54551",
    "CVE-2024-54564",
    "CVE-2024-6387"
  );
  script_xref(name:"APPLE-SA", value:"120911");
  script_xref(name:"IAVA", value:"2024-A-0578-S");

  script_name(english:"macOS 14.x < 14.6 Multiple Vulnerabilities (120911)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.6. It is, therefore, affected by
multiple vulnerabilities:

  - A race condition in sshd affecting versions between 8.5p1 and 9.7p1 (inclusive) may allow arbitrary code
    execution with root privileges. Successful exploitation has been demonstrated on 32-bit Linux/glibc
    systems with ASLR. According to OpenSSH, the attack has been tested under lab conditions and requires on
    average 6-8 hours of continuous connections up to the maximum the server will accept. Exploitation on
    64-bit systems is believed to be possible but has not been demonstrated at this time.  (CVE-2024-6387)

  - A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition
    which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be
    able to trigger it by failing to authenticate within a set time period. (CVE-2024-6387)

  - Use after free in ANGLE in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4558)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Ventura 13.3. An app
    may bypass Gatekeeper checks. (CVE-2023-27952)

  - Faulty input validation in the core of Apache allows malicious or exploitable backend/content generators
    to split HTTP responses. This issue affects Apache HTTP Server: through 2.4.58. (CVE-2023-38709)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120911");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4558");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '14.6.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.6' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
