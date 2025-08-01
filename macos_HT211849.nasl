#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141099);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2020-9941",
    "CVE-2020-9961",
    "CVE-2020-9968",
    "CVE-2020-9973"
  );
  script_xref(name:"APPLE-SA", value:"HT211849");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-09-24");
  script_xref(name:"IAVA", value:"2020-A-0441-S");

  script_name(english:"macOS 10.13.x < 10.13.6 Security Update 2020-005 / 10.14.x < 10.14.6 Security Update 2020-005 / 10.15.x < 10.15.7");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.13.x prior to 10.13.6 Security Update 2020-005,
10.14.x prior to 10.14.6 Security Update 2020-005, or 10.15.x prior to 10.15.7. It is, therefore, affected by multiple
vulnerabilities, as follows:

  - Processing a maliciously crafted image may lead to arbitrary code execution. (CVE-2020-9961)

  - A remote attacker may be able to unexpectedly alter application state. (CVE-2020-9941)

  - Processing a maliciously crafted USD file may lead to unexpected application termination or arbitrary
    code execution. (CVE-2020-9973)

  - A malicious application may be able to access restricted files. (CVE-2020-9968)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211849");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.13.6 Security Update 2020-005 / 10.14.6 Security Update 2020-005 / 10.15.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:10.15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:10.13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:10.14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:10.15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.15.6', 'min_version' : '10.15', 'fixed_build': '19H2', 'fixed_display' : 'macOS Catalina 10.15.7' },
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build': '17G14033', 'fixed_display' : '10.13.6 Security Update 2020-005' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G6032', 'fixed_display' : '10.14.6 Security Update 2020-005' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
