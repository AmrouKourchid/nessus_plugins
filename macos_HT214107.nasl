#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196931);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id(
    "CVE-2023-42861",
    "CVE-2024-23296",
    "CVE-2024-27789",
    "CVE-2024-27796",
    "CVE-2024-27798",
    "CVE-2024-27799",
    "CVE-2024-27800",
    "CVE-2024-27802",
    "CVE-2024-27805",
    "CVE-2024-27806",
    "CVE-2024-27810",
    "CVE-2024-27817",
    "CVE-2024-27823",
    "CVE-2024-27824",
    "CVE-2024-27827",
    "CVE-2024-27831",
    "CVE-2024-27840",
    "CVE-2024-27843",
    "CVE-2024-27847",
    "CVE-2024-27855",
    "CVE-2024-27885"
  );
  script_xref(name:"APPLE-SA", value:"HT214107");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/27");
  script_xref(name:"IAVA", value:"2024-A-0275-S");
  script_xref(name:"IAVA", value:"2024-A-0455-S");

  script_name(english:"macOS 13.x < 13.6.7 Multiple Vulnerabilities (HT214107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.6.7. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Sonoma 14.1. An
    attacker with knowledge of a standard user's credentials can unlock another standard user's locked screen
    on the same Mac. (CVE-2023-42861)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 17.4 and
    iPadOS 17.4. An attacker with arbitrary kernel read and write capability may be able to bypass kernel
    memory protections. Apple is aware of a report that this issue may have been exploited. (CVE-2024-23296)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.7.8 and iPadOS 16.7.8,
    macOS Monterey 12.7.5, macOS Ventura 13.6.7, macOS Sonoma 14.4. An app may be able to access user-
    sensitive data. (CVE-2024-27789)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.5 and iPadOS 17.5, macOS
    Sonoma 14.5. An attacker may be able to elevate privileges. (CVE-2024-27796)

  - An authorization issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.5. An attacker may be able to elevate privileges. (CVE-2024-27798)

  - This issue was addressed with additional entitlement checks. This issue is fixed in macOS Sonoma 14.5,
    macOS Ventura 13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8. An unprivileged app may be able
    to log keystrokes in other apps including those using secure input mode. (CVE-2024-27799)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Ventura 13.6.7,
    macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5,
    watchOS 10.5, macOS Sonoma 14.5. Processing a maliciously crafted message may lead to a denial-of-service.
    (CVE-2024-27800)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS
    17.5, macOS Sonoma 14.5. Processing a maliciously crafted file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2024-27802)

  - An issue was addressed with improved validation of environment variables. This issue is fixed in macOS
    Ventura 13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, iOS 17.5 and iPadOS 17.5,
    watchOS 10.5, macOS Sonoma 14.5. An app may be able to access sensitive user data. (CVE-2024-27805)

  - This issue was addressed with improved environment sanitization. This issue is fixed in macOS Ventura
    13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, iOS 17.5 and iPadOS 17.5, watchOS
    10.5, macOS Sonoma 14.5. An app may be able to access sensitive user data. (CVE-2024-27806)

  - A path handling issue was addressed with improved validation. This issue is fixed in iOS 17.5 and iPadOS
    17.5, tvOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to read sensitive location
    information. (CVE-2024-27810)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.6.7, macOS Monterey
    12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5, macOS Sonoma
    14.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2024-27817)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Sonoma 14.5, iOS 16.7.8
    and iPadOS 16.7.8, macOS Ventura 13.6.7, watchOS 10.5, visionOS 1.3, tvOS 17.5, iOS 17.5 and iPadOS 17.5,
    macOS Monterey 12.7.5. An attacker in a privileged network position may be able to spoof network packets.
    (CVE-2024-27823)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.5. An app
    may be able to elevate privileges. (CVE-2024-27824)

  - This issue was addressed through improved state management. This issue is fixed in macOS Sonoma 14.5. An
    app may be able to read arbitrary files. (CVE-2024-27827)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and
    iPadOS 17.5, macOS Sonoma 14.5. Processing a file may lead to unexpected app termination or arbitrary code
    execution. (CVE-2024-27831)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6.7, macOS
    Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5, watchOS
    10.5. An attacker that has already achieved kernel code execution may be able to bypass kernel memory
    protections. (CVE-2024-27840)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app may be
    able to elevate privileges. (CVE-2024-27843)

  - This issue was addressed with improved checks This issue is fixed in iOS 17.5 and iPadOS 17.5, macOS
    Sonoma 14.5. An app may be able to bypass Privacy preferences. (CVE-2024-27847)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5, macOS Ventura
    13.6.7, iOS 17.5 and iPadOS 17.5, iOS 16.7.8 and iPadOS 16.7.8. A shortcut may be able to use sensitive
    data with certain actions without prompting the user. (CVE-2024-27855)

  - This issue was addressed with improved validation of symlinks. This issue is fixed in macOS Sonoma 14.5,
    macOS Ventura 13.6.7, macOS Monterey 12.7.5. An app may be able to modify protected parts of the file
    system. (CVE-2024-27885)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214107");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27855");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.6.7', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.6.7' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
