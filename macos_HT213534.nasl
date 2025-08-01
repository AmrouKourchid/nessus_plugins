#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168670);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2022-32942",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2022-42821",
    "CVE-2022-42840",
    "CVE-2022-42841",
    "CVE-2022-42842",
    "CVE-2022-42845",
    "CVE-2022-42864",
    "CVE-2022-42865",
    "CVE-2022-46689",
    "CVE-2022-46704",
    "CVE-2022-46718"
  );
  script_xref(name:"APPLE-SA", value:"HT213534");
  script_xref(name:"IAVA", value:"2022-A-0524-S");
  script_xref(name:"IAVA", value:"2023-A-0645");

  script_name(english:"macOS 11.x < 11.7.2 Multiple Vulnerabilities (HT213534)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.7.2. It is, therefore, affected by
multiple vulnerabilities:

  - This issue was addressed by enabling hardened runtime. This issue is fixed in iOS 16.2 and iPadOS 16.2,
    macOS Ventura 13.1, tvOS 16.2, watchOS 9.2. An app may be able to bypass Privacy preferences.
    (CVE-2022-42865)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.2, macOS Big
    Sur 11.7.2, macOS Ventura 13. An app may bypass Gatekeeper checks. (CVE-2022-42821)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.2, macOS
    Ventura 13.1, macOS Big Sur 11.7.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32942)

  - A race condition was addressed with improved state handling. This issue is fixed in tvOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and
    iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-42864)

  - A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS
    Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and
    iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-46689)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.2, macOS Monterey
    12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app with root
    privileges may be able to execute arbitrary code with kernel privileges. (CVE-2022-42845)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.2, macOS Monterey
    12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. A remote user may
    be able to cause kernel code execution. (CVE-2022-42842)

  - An issue was discovered in libxml2 before 2.10.3. When parsing a multi-gigabyte XML document with the
    XML_PARSE_HUGE parser option enabled, several integer counters can overflow. This results in an attempt to
    access an array at a negative 2GB offset, typically leading to a segmentation fault. (CVE-2022-40303)

  - An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a
    hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be
    provoked. (CVE-2022-40304)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.1,
    macOS Big Sur 11.7.2, macOS Monterey 12.6.2. An app may be able to modify protected parts of the file
    system. (CVE-2022-46704)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.2, macOS
    Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2. An app may be
    able to execute arbitrary code with kernel privileges. (CVE-2022-42840)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 15.7.2 and iPadOS
    15.7.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, macOS Monterey 12.6.2. An app may be able to read
    sensitive location information (CVE-2022-46718)

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.2,
    macOS Ventura 13.1, macOS Big Sur 11.7.2. Processing a maliciously crafted package may lead to arbitrary
    code execution. (CVE-2022-42841)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213534");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'macOS Dirty Cow Arbitrary File Write Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '11.7.2', 'min_version' : '11.0', 'fixed_display' : 'macOS Big Sur 11.7.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
