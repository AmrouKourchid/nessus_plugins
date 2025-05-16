#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176087);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/24");

  script_cve_id(
    "CVE-2023-23535",
    "CVE-2023-27940",
    "CVE-2023-27945",
    "CVE-2023-28191",
    "CVE-2023-32352",
    "CVE-2023-32355",
    "CVE-2023-32357",
    "CVE-2023-32360",
    "CVE-2023-32368",
    "CVE-2023-32369",
    "CVE-2023-32375",
    "CVE-2023-32380",
    "CVE-2023-32382",
    "CVE-2023-32383",
    "CVE-2023-32384",
    "CVE-2023-32386",
    "CVE-2023-32387",
    "CVE-2023-32388",
    "CVE-2023-32392",
    "CVE-2023-32395",
    "CVE-2023-32397",
    "CVE-2023-32398",
    "CVE-2023-32401",
    "CVE-2023-32403",
    "CVE-2023-32405",
    "CVE-2023-32407",
    "CVE-2023-32408",
    "CVE-2023-32410",
    "CVE-2023-32411",
    "CVE-2023-32412",
    "CVE-2023-32413",
    "CVE-2023-32428"
  );
  script_xref(name:"APPLE-SA", value:"HT213759");
  script_xref(name:"IAVA", value:"2023-A-0264-S");

  script_name(english:"macOS 12.x < 12.6.6 Multiple Vulnerabilities (HT213759)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.6.6. It is, therefore, affected by
multiple vulnerabilities:

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    watchOS 9.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey
    12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to bypass Privacy preferences. (CVE-2023-32388)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    9.5, tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5.
    An app may be able to bypass Privacy preferences. (CVE-2023-28191)

  - This issue was addressed with improved entitlements. This issue is fixed in tvOS 16.5, macOS Ventura 13.4,
    macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to bypass
    Privacy preferences. (CVE-2023-32411)

  - This issue was addressed by forcing hardened runtime on the affected binaries at the system level. This
    issue is fixed in macOS Monterey 12.6.6, macOS Big Sur 11.7.7, macOS Ventura 13.4. An app may be able to
    inject code into sensitive binaries bundled with Xcode. (CVE-2023-32383)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS Big
    Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to observe unprotected user
    data. (CVE-2023-32386)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An unauthenticated user may be able to access recently
    printed documents. (CVE-2023-32360)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. A remote attacker may be able to cause unexpected app
    termination or arbitrary code execution. (CVE-2023-32387)

  - This issue was addressed with improved entitlements. This issue is fixed in Xcode 14.3, macOS Big Sur
    11.7.7, macOS Monterey 12.6.6. A sandboxed app may be able to collect system logs. (CVE-2023-27945)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    watchOS 9.5, tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and
    iPadOS 16.5. An app may be able to read sensitive location information. (CVE-2023-32392)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.3, iOS 16.4
    and iPadOS 16.4, macOS Big Sur 11.7.5, iOS 15.7.4 and iPadOS 15.7.4, macOS Monterey 12.6.6, tvOS 16.4,
    watchOS 9.4. Processing a maliciously crafted image may result in disclosure of process memory.
    (CVE-2023-23535)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in watchOS 9.5, tvOS
    16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS
    16.5 and iPadOS 16.5. Processing an image may lead to arbitrary code execution. (CVE-2023-32384)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 15.7.6 and
    iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to leak
    sensitive kernel state. (CVE-2023-32410)

  - The issue was addressed with additional permissions checks. This issue is fixed in iOS 15.7.6 and iPadOS
    15.7.6, macOS Monterey 12.6.6, macOS Ventura 13.4. A sandboxed app may be able to observe system-wide
    network connections. (CVE-2023-27940)

  - A race condition was addressed with improved state handling. This issue is fixed in watchOS 9.5, tvOS
    16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS
    16.5 and iPadOS 16.5. An app may be able to gain root privileges. (CVE-2023-32413)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6,
    iOS 16.5 and iPadOS 16.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-32398)

  - A logic issue was addressed with improved checks. This issue is fixed in watchOS 9.5, macOS Ventura 13.4,
    macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app may bypass Gatekeeper
    checks. (CVE-2023-32352)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7.7,
    macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to modify protected parts of the file
    system. (CVE-2023-32355, CVE-2023-32369, CVE-2023-32395)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.7.7, macOS
    Monterey 12.6.6, macOS Ventura 13.4. An app may be able to gain root privileges. (CVE-2023-32405)

  - This issue was addressed with improved file handling. This issue is fixed in macOS Ventura 13.4, tvOS
    16.5, iOS 16.5 and iPadOS 16.5, watchOS 9.5. An app may be able to gain root privileges. (CVE-2023-32428)

  - A logic issue was addressed with improved state management. This issue is fixed in watchOS 9.5, tvOS 16.5,
    macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5
    and iPadOS 16.5. An app may be able to bypass Privacy preferences. (CVE-2023-32407)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. Processing a 3D model may
    result in disclosure of process memory. (CVE-2023-32368)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Monterey
    12.6.6, macOS Ventura 13.4. Processing a 3D model may result in disclosure of process memory.
    (CVE-2023-32375)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. Processing a 3D model may result in disclosure of
    process memory. (CVE-2023-32382)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Big
    Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. Processing a 3D model may lead to arbitrary code
    execution. (CVE-2023-32380)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    9.5, tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey
    12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to read sensitive location information.
    (CVE-2023-32403)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in macOS Monterey
    12.6.6, macOS Big Sur 11.7.7, macOS Ventura 13.4. Parsing an office document may lead to an unexpected app
    termination or arbitrary code execution. (CVE-2023-32401)

  - An authorization issue was addressed with improved state management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An
    app may be able to retain access to system configuration files even after its permission is revoked.
    (CVE-2023-32357)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.7.6 and iPadOS
    15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to modify
    protected parts of the file system. (CVE-2023-32397)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6,
    iOS 16.5 and iPadOS 16.5. A remote attacker may be able to cause unexpected app termination or arbitrary
    code execution. (CVE-2023-32412)

  - The issue was addressed with improved handling of caches. This issue is fixed in watchOS 9.5, tvOS 16.5,
    macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app
    may be able to read sensitive location information. (CVE-2023-32408)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213759");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32412");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '12.6.6', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.6.6' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
