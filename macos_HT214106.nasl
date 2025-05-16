#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196912);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id(
    "CVE-2023-42893",
    "CVE-2024-23236",
    "CVE-2024-23251",
    "CVE-2024-23282",
    "CVE-2024-27796",
    "CVE-2024-27798",
    "CVE-2024-27799",
    "CVE-2024-27800",
    "CVE-2024-27801",
    "CVE-2024-27802",
    "CVE-2024-27804",
    "CVE-2024-27805",
    "CVE-2024-27806",
    "CVE-2024-27808",
    "CVE-2024-27810",
    "CVE-2024-27811",
    "CVE-2024-27813",
    "CVE-2024-27815",
    "CVE-2024-27816",
    "CVE-2024-27817",
    "CVE-2024-27818",
    "CVE-2024-27820",
    "CVE-2024-27821",
    "CVE-2024-27822",
    "CVE-2024-27823",
    "CVE-2024-27824",
    "CVE-2024-27825",
    "CVE-2024-27826",
    "CVE-2024-27827",
    "CVE-2024-27829",
    "CVE-2024-27830",
    "CVE-2024-27831",
    "CVE-2024-27832",
    "CVE-2024-27834",
    "CVE-2024-27836",
    "CVE-2024-27837",
    "CVE-2024-27838",
    "CVE-2024-27841",
    "CVE-2024-27842",
    "CVE-2024-27843",
    "CVE-2024-27844",
    "CVE-2024-27847",
    "CVE-2024-27848",
    "CVE-2024-27850",
    "CVE-2024-27851",
    "CVE-2024-27855",
    "CVE-2024-27857",
    "CVE-2024-27884",
    "CVE-2024-27885"
  );
  script_xref(name:"APPLE-SA", value:"HT214106");
  script_xref(name:"IAVA", value:"2024-A-0275-S");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 14.x < 14.5 Multiple Vulnerabilities (HT214106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.5. It is, therefore, affected by
multiple vulnerabilities:

  - A permissions issue was addressed by removing vulnerable code and adding additional checks. This issue is
    fixed in macOS Monterey 12.7.2, macOS Ventura 13.6.3, iOS 17.2 and iPadOS 17.2, iOS 16.7.3 and iPadOS
    16.7.3, tvOS 17.2, watchOS 10.2, macOS Sonoma 14.2. An app may be able to access protected user data.
    (CVE-2023-42893)

  - A correctness issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app
    may be able to read arbitrary files. (CVE-2024-23236)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.5, watchOS 10.5, iOS 17.5 and iPadOS 17.5, iOS 16.7.8 and iPadOS 16.7.8. An attacker with physical
    access may be able to leak Mail account credentials. (CVE-2024-23251)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5, watchOS 10.5, iOS
    17.5 and iPadOS 17.5, iOS 16.7.8 and iPadOS 16.7.8. A maliciously crafted email may be able to initiate
    FaceTime calls without user authorization. (CVE-2024-23282)

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

  - The issue was addressed with improved checks. This issue is fixed in tvOS 17.5, visionOS 1.2, iOS 17.5 and
    iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to elevate privileges. (CVE-2024-27801,
    CVE-2024-27811, CVE-2024-27832)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Ventura
    13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS
    17.5, macOS Sonoma 14.5. Processing a maliciously crafted file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2024-27802)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.5 and iPadOS 17.5,
    tvOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to execute arbitrary code with kernel
    privileges. (CVE-2024-27804)

  - An issue was addressed with improved validation of environment variables. This issue is fixed in macOS
    Ventura 13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, iOS 17.5 and iPadOS 17.5,
    watchOS 10.5, macOS Sonoma 14.5. An app may be able to access sensitive user data. (CVE-2024-27805)

  - This issue was addressed with improved environment sanitization. This issue is fixed in macOS Ventura
    13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, iOS 17.5 and iPadOS 17.5, watchOS
    10.5, macOS Sonoma 14.5. An app may be able to access sensitive user data. (CVE-2024-27806)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 17.5, visionOS 1.2,
    Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. Processing web content may lead to
    arbitrary code execution. (CVE-2024-27808)

  - A path handling issue was addressed with improved validation. This issue is fixed in iOS 17.5 and iPadOS
    17.5, tvOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to read sensitive location
    information. (CVE-2024-27810)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app may be able
    to execute arbitrary code out of its sandbox or with certain elevated privileges. (CVE-2024-27813)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in tvOS
    17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. An app may be able to
    execute arbitrary code with kernel privileges. (CVE-2024-27815)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.5 and iPadOS 17.5, tvOS
    17.5, watchOS 10.5, macOS Sonoma 14.5. An attacker may be able to access user data. (CVE-2024-27816)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.6.7, macOS Monterey
    12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5, macOS Sonoma
    14.5. An app may be able to execute arbitrary code with kernel privileges. (CVE-2024-27817)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.5 and iPadOS 17.5,
    macOS Sonoma 14.5. An attacker may be able to cause unexpected app termination or arbitrary code
    execution. (CVE-2024-27818)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 17.5, iOS 16.7.8 and
    iPadOS 16.7.8, visionOS 1.2, Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5.
    Processing web content may lead to arbitrary code execution. (CVE-2024-27820)

  - A path handling issue was addressed with improved validation. This issue is fixed in iOS 17.5 and iPadOS
    17.5, watchOS 10.5, macOS Sonoma 14.5. A shortcut may output sensitive user data without consent.
    (CVE-2024-27821)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.5. An app
    may be able to gain root privileges. (CVE-2024-27822)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Sonoma 14.5, iOS 16.7.8
    and iPadOS 16.7.8, macOS Ventura 13.6.7, watchOS 10.5, visionOS 1.3, tvOS 17.5, iOS 17.5 and iPadOS 17.5,
    macOS Monterey 12.7.5. An attacker in a privileged network position may be able to spoof network packets.
    (CVE-2024-27823)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.5. An app
    may be able to elevate privileges. (CVE-2024-27824)

  - A downgrade issue affecting Intel-based Mac computers was addressed with additional code-signing
    restrictions. This issue is fixed in macOS Sonoma 14.5. An app may be able to bypass certain Privacy
    preferences. (CVE-2024-27825)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6.8, macOS
    Sonoma 14.5, macOS Monterey 12.7.6, watchOS 10.5, visionOS 1.3, tvOS 17.5, iOS 17.5 and iPadOS 17.5. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2024-27826)

  - This issue was addressed through improved state management. This issue is fixed in macOS Sonoma 14.5. An
    app may be able to read arbitrary files. (CVE-2024-27827)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.5.
    Processing a file may lead to unexpected app termination or arbitrary code execution. (CVE-2024-27829)

  - This issue was addressed through improved state management. This issue is fixed in tvOS 17.5, visionOS
    1.2, Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. A maliciously crafted webpage
    may be able to fingerprint the user. (CVE-2024-27830)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Ventura 13.6.7, macOS Monterey 12.7.5, iOS 16.7.8 and iPadOS 16.7.8, tvOS 17.5, visionOS 1.2, iOS 17.5 and
    iPadOS 17.5, macOS Sonoma 14.5. Processing a file may lead to unexpected app termination or arbitrary code
    execution. (CVE-2024-27831)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.5 and iPadOS 17.5, tvOS 17.5,
    Safari 17.5, watchOS 10.5, macOS Sonoma 14.5. An attacker with arbitrary read and write capability may be
    able to bypass Pointer Authentication. (CVE-2024-27834)

  - The issue was addressed with improved checks. This issue is fixed in visionOS 1.2, macOS Sonoma 14.5, iOS
    17.5 and iPadOS 17.5. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2024-27836)

  - A downgrade issue was addressed with additional code-signing restrictions. This issue is fixed in macOS
    Sonoma 14.5. A local attacker may gain access to Keychain items. (CVE-2024-27837)

  - The issue was addressed by adding additional logic. This issue is fixed in tvOS 17.5, iOS 16.7.8 and
    iPadOS 16.7.8, visionOS 1.2, Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. A
    maliciously crafted webpage may be able to fingerprint the user. (CVE-2024-27838)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.5 and iPadOS 17.5,
    macOS Sonoma 14.5. An app may be able to disclose kernel memory. (CVE-2024-27841)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app may be able
    to execute arbitrary code with kernel privileges. (CVE-2024-27842)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app may be
    able to elevate privileges. (CVE-2024-27843)

  - The issue was addressed with improved checks. This issue is fixed in visionOS 1.2, macOS Sonoma 14.5,
    Safari 17.5. A website's permission dialog may persist after navigation away from the site.
    (CVE-2024-27844)

  - This issue was addressed with improved checks This issue is fixed in iOS 17.5 and iPadOS 17.5, macOS
    Sonoma 14.5. An app may be able to bypass Privacy preferences. (CVE-2024-27847)

  - This issue was addressed with improved permissions checking. This issue is fixed in macOS Sonoma 14.5, iOS
    17.5 and iPadOS 17.5. A malicious app may be able to gain root privileges. (CVE-2024-27848)

  - This issue was addressed with improvements to the noise injection algorithm. This issue is fixed in
    visionOS 1.2, macOS Sonoma 14.5, Safari 17.5, iOS 17.5 and iPadOS 17.5. A maliciously crafted webpage may
    be able to fingerprint the user. (CVE-2024-27850)

  - The issue was addressed with improved bounds checks. This issue is fixed in tvOS 17.5, visionOS 1.2,
    Safari 17.5, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2024-27851)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5, macOS Ventura
    13.6.7, iOS 17.5 and iPadOS 17.5, iOS 16.7.8 and iPadOS 16.7.8. A shortcut may be able to use sensitive
    data with certain actions without prompting the user. (CVE-2024-27855)

  - An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in visionOS
    1.2, macOS Sonoma 14.5, tvOS 17.5, iOS 17.5 and iPadOS 17.5. A remote attacker may be able to cause
    unexpected app termination or arbitrary code execution. (CVE-2024-27857)

  - This issue was addressed with a new entitlement. This issue is fixed in macOS Sonoma 14.5, watchOS 10.5,
    visionOS 1.2, tvOS 17.5, iOS 17.5 and iPadOS 17.5. An app may be able to access user-sensitive data.
    (CVE-2024-27884)

  - This issue was addressed with improved validation of symlinks. This issue is fixed in macOS Sonoma 14.5,
    macOS Ventura 13.6.7, macOS Monterey 12.7.5. An app may be able to modify protected parts of the file
    system. (CVE-2024-27885)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214106");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27855");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/13");

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
  { 'fixed_version' : '14.5.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
