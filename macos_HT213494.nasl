#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166599);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id(
    "CVE-2022-28739",
    "CVE-2022-32862",
    "CVE-2022-32941",
    "CVE-2022-32944",
    "CVE-2022-37434",
    "CVE-2022-42798",
    "CVE-2022-42800",
    "CVE-2022-42801",
    "CVE-2022-42803",
    "CVE-2022-42823",
    "CVE-2022-42825",
    "CVE-2022-42860",
    "CVE-2022-46713",
    "CVE-2022-46723"
  );
  script_xref(name:"APPLE-SA", value:"HT213494");
  script_xref(name:"IAVA", value:"2022-A-0442-S");

  script_name(english:"macOS 12.x < 12.6.1 Multiple Vulnerabilities (HT213494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6.1. It is, therefore, affected by
multiple vulnerabilities:

  - This issue was addressed by removing additional entitlements. This issue is fixed in tvOS 16.1, macOS
    Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1, macOS Big Sur 11.7.1. An app may
    be able to modify protected parts of the file system. (CVE-2022-42825)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 16.1, iOS 15.7.1 and
    iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1, macOS Big Sur
    11.7.1. Parsing a maliciously crafted audio file may lead to disclosure of user information.
    (CVE-2022-42798)

  - This issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in
    macOS Monterey 12.6.1, macOS Big Sur 11.7.1, macOS Ventura 13. An app may be able to modify protected
    parts of the file system (CVE-2022-42860)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.6.1, macOS Big Sur
    11.7.1. A remote user may be able to write arbitrary files. (CVE-2022-46723)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 16.1,
    iOS 15.7.1 and iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey
    12.6.1, macOS Big Sur 11.7.1. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-32944)

  - A race condition was addressed with improved locking. This issue is fixed in tvOS 16.1, iOS 15.7.1 and
    iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1. An app may be
    able to execute arbitrary code with kernel privileges. (CVE-2022-42803)

  - A logic issue was addressed with improved checks. This issue is fixed in tvOS 16.1, iOS 15.7.1 and iPadOS
    15.7.1, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1. An app may be able
    to execute arbitrary code with kernel privileges. (CVE-2022-42801)

  - A race condition was addressed with additional validation. This issue is fixed in macOS Ventura 13, macOS
    Monterey 12.6.1, macOS Big Sur 11.7.1. An app may be able to modify protected parts of the file system.
    (CVE-2022-46713)

  - The issue was addressed with improved bounds checks. This issue is fixed in iOS 15.7.1 and iPadOS 15.7.1,
    macOS Ventura 13, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1, macOS Big Sur 11.7.1. A buffer overflow
    may result in arbitrary code execution. (CVE-2022-32941)

  - There is a buffer over-read in Ruby before 2.6.10, 2.7.x before 2.7.6, 3.x before 3.0.4, and 3.1.x before
    3.1.2. It occurs in String-to-Float conversion, including Kernel#Float and String#to_f. (CVE-2022-28739)

  - This issue was addressed with improved data protection. This issue is fixed in macOS Big Sur 11.7.1, macOS
    Ventura 13, macOS Monterey 12.6.1. An app with root privileges may be able to access private information.
    (CVE-2022-32862)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in tvOS 16.1,
    macOS Ventura 13, watchOS 9.1, Safari 16.1, iOS 16.1 and iPadOS 16. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-42823)

  - zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a
    large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some
    common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g.,
    see the nodejs/node reference). (CVE-2022-37434)

  - This issue was addressed with improved checks. This issue is fixed in iOS 15.7.1 and iPadOS 15.7.1, macOS
    Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1, macOS Big Sur 11.7.1. A user may
    be able to cause unexpected app termination or arbitrary code execution. (CVE-2022-42800)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213494");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28739");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46723");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
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
  { 'fixed_version' : '12.6.1', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.6.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
