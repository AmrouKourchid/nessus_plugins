#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154775);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2021-30821",
    "CVE-2021-30824",
    "CVE-2021-30834",
    "CVE-2021-30876",
    "CVE-2021-30877",
    "CVE-2021-30879",
    "CVE-2021-30880",
    "CVE-2021-30881",
    "CVE-2021-30892",
    "CVE-2021-30899",
    "CVE-2021-30901",
    "CVE-2021-30905",
    "CVE-2021-30907",
    "CVE-2021-30909",
    "CVE-2021-30910",
    "CVE-2021-30911",
    "CVE-2021-30912",
    "CVE-2021-30915",
    "CVE-2021-30916",
    "CVE-2021-30917",
    "CVE-2021-30919"
  );
  script_xref(name:"APPLE-SA", value:"HT212871");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-10-26-5");
  script_xref(name:"IAVA", value:"2021-A-0505-S");

  script_name(english:"macOS 10.15.x < Catalina Security Update 2021-007 Catalina (HT212871)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is prior to Catalina Security Update 2021-007. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.0.1,
    Security Update 2021-007 Catalina, macOS Big Sur 11.6.1. A malicious application may be able to execute
    arbitrary code with kernel privileges. (CVE-2021-30899)

  - A memory corruption issue existed in the processing of ICC profiles. This issue was addressed with
    improved input validation. This issue is fixed in iOS 15.1 and iPadOS 15.1, macOS Monterey 12.0.1, iOS
    14.8.1 and iPadOS 14.8.1, tvOS 15.1, watchOS 8.1, Security Update 2021-007 Catalina, macOS Big Sur 11.6.1.
    Processing a maliciously crafted image may lead to arbitrary code execution. (CVE-2021-30917)

  - An out-of-bounds write was addressed with improved input validation. This issue is fixed in iOS 15.1 and
    iPadOS 15.1, macOS Monterey 12.0.1, iOS 14.8.1 and iPadOS 14.8.1, tvOS 15.1, watchOS 8.1, Security Update
    2021-007 Catalina, macOS Big Sur 11.6.1. Processing a maliciously crafted PDF may lead to arbitrary code
    execution. (CVE-2021-30919)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212871");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Catalina Security Update 2021-007 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30916");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30919");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:10.15");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  {
    'max_version' : '10.15.7',
    'min_version' : '10.15',
    'fixed_build'  : '19H1519',
    'fixed_display' : 'Catalina 10.15.7 Security Update 2021-007'
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
