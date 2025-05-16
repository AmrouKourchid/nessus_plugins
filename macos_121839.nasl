#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212421);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2023-32395",
    "CVE-2024-40864",
    "CVE-2024-44220",
    "CVE-2024-44224",
    "CVE-2024-44225",
    "CVE-2024-44243",
    "CVE-2024-44245",
    "CVE-2024-44246",
    "CVE-2024-44291",
    "CVE-2024-44300",
    "CVE-2024-45306",
    "CVE-2024-45490",
    "CVE-2024-54465",
    "CVE-2024-54466",
    "CVE-2024-54468",
    "CVE-2024-54474",
    "CVE-2024-54475",
    "CVE-2024-54476",
    "CVE-2024-54477",
    "CVE-2024-54478",
    "CVE-2024-54479",
    "CVE-2024-54484",
    "CVE-2024-54485",
    "CVE-2024-54486",
    "CVE-2024-54488",
    "CVE-2024-54489",
    "CVE-2024-54490",
    "CVE-2024-54491",
    "CVE-2024-54492",
    "CVE-2024-54493",
    "CVE-2024-54494",
    "CVE-2024-54495",
    "CVE-2024-54497",
    "CVE-2024-54498",
    "CVE-2024-54499",
    "CVE-2024-54500",
    "CVE-2024-54501",
    "CVE-2024-54502",
    "CVE-2024-54504",
    "CVE-2024-54505",
    "CVE-2024-54506",
    "CVE-2024-54507",
    "CVE-2024-54508",
    "CVE-2024-54509",
    "CVE-2024-54510",
    "CVE-2024-54513",
    "CVE-2024-54514",
    "CVE-2024-54515",
    "CVE-2024-54516",
    "CVE-2024-54517",
    "CVE-2024-54518",
    "CVE-2024-54519",
    "CVE-2024-54520",
    "CVE-2024-54522",
    "CVE-2024-54523",
    "CVE-2024-54524",
    "CVE-2024-54525",
    "CVE-2024-54526",
    "CVE-2024-54527",
    "CVE-2024-54528",
    "CVE-2024-54529",
    "CVE-2024-54530",
    "CVE-2024-54531",
    "CVE-2024-54533",
    "CVE-2024-54534",
    "CVE-2024-54536",
    "CVE-2024-54537",
    "CVE-2024-54539",
    "CVE-2024-54541",
    "CVE-2024-54542",
    "CVE-2024-54543",
    "CVE-2024-54547",
    "CVE-2024-54549",
    "CVE-2024-54550",
    "CVE-2024-54557",
    "CVE-2024-54559",
    "CVE-2024-54565"
  );
  script_xref(name:"APPLE-SA", value:"121839");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 15.x < 15.2 Multiple Vulnerabilities (121839)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.2. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved memory handling. This issue is fixed in visionOS 2.2, tvOS 18.2,
    Safari 18.2, watchOS 11.2, iOS 18.2 and iPadOS 18.2, macOS Sequoia 15.2. Processing maliciously crafted
    web content may lead to memory corruption. (CVE-2024-54543)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 11.2, visionOS 2.2,
    tvOS 18.2, macOS Sequoia 15.2, Safari 18.2, iOS 18.2 and iPadOS 18.2. Processing maliciously crafted web
    content may lead to memory corruption. (CVE-2024-54534)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7.7,
    macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to modify protected parts of the file
    system. (CVE-2023-32395)

  - The issue was addressed with improved handling of protocols. This issue is fixed in macOS Ventura 13.7.5,
    macOS Sonoma 14.7.5. An attacker in a privileged network position can track a user's activity.
    (CVE-2024-40864)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sequoia 15.2, macOS
    Sonoma 14.7.2. Parsing a maliciously crafted video file may lead to unexpected system termination.
    (CVE-2024-44220)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54543");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-54534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
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
  { 'fixed_version' : '15.2.0', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
