#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212417);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id(
    "CVE-2024-44201",
    "CVE-2024-44220",
    "CVE-2024-44224",
    "CVE-2024-44225",
    "CVE-2024-44245",
    "CVE-2024-44248",
    "CVE-2024-44291",
    "CVE-2024-44300",
    "CVE-2024-45306",
    "CVE-2024-45490",
    "CVE-2024-54466",
    "CVE-2024-54468",
    "CVE-2024-54474",
    "CVE-2024-54475",
    "CVE-2024-54476",
    "CVE-2024-54477",
    "CVE-2024-54478",
    "CVE-2024-54486",
    "CVE-2024-54488",
    "CVE-2024-54489",
    "CVE-2024-54494",
    "CVE-2024-54495",
    "CVE-2024-54498",
    "CVE-2024-54500",
    "CVE-2024-54501",
    "CVE-2024-54509",
    "CVE-2024-54510",
    "CVE-2024-54514",
    "CVE-2024-54516",
    "CVE-2024-54519",
    "CVE-2024-54520",
    "CVE-2024-54526",
    "CVE-2024-54527",
    "CVE-2024-54528",
    "CVE-2024-54529",
    "CVE-2024-54537",
    "CVE-2024-54539",
    "CVE-2024-54541",
    "CVE-2024-54547",
    "CVE-2024-54557"
  );
  script_xref(name:"APPLE-SA", value:"121840");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 14.x < 14.7.2 Multiple Vulnerabilities (121840)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.7.2. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.7.2, macOS
    Sequoia 15.2, macOS Ventura 13.7.2. An attacker may gain access to protected parts of the file system.
    (CVE-2024-54557)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Sequoia 15.2,
    macOS Ventura 13.7.2, macOS Sonoma 14.7.2. An app may be able to break out of its sandbox.
    (CVE-2024-54498)

  - The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.3, macOS Ventura
    13.7.2, iOS 18.1 and iPadOS 18.1, macOS Sonoma 14.7.2. Processing a malicious crafted file may lead to a
    denial-of-service. (CVE-2024-44201)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sequoia 15.2, macOS
    Sonoma 14.7.2. Parsing a maliciously crafted video file may lead to unexpected system termination.
    (CVE-2024-44220)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sequoia 15.2,
    macOS Ventura 13.7.2, macOS Sonoma 14.7.2. A malicious app may be able to gain root privileges.
    (CVE-2024-44224)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121840");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54557");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-54498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

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
  { 'fixed_version' : '14.7.2', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.7.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
