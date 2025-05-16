#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176078);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_cve_id(
    "CVE-2023-22809",
    "CVE-2023-27930",
    "CVE-2023-27940",
    "CVE-2023-28191",
    "CVE-2023-28202",
    "CVE-2023-28204",
    "CVE-2023-29469",
    "CVE-2023-32352",
    "CVE-2023-32355",
    "CVE-2023-32357",
    "CVE-2023-32360",
    "CVE-2023-32363",
    "CVE-2023-32367",
    "CVE-2023-32368",
    "CVE-2023-32369",
    "CVE-2023-32371",
    "CVE-2023-32372",
    "CVE-2023-32373",
    "CVE-2023-32375",
    "CVE-2023-32376",
    "CVE-2023-32379",
    "CVE-2023-32380",
    "CVE-2023-32382",
    "CVE-2023-32383",
    "CVE-2023-32384",
    "CVE-2023-32385",
    "CVE-2023-32386",
    "CVE-2023-32387",
    "CVE-2023-32388",
    "CVE-2023-32389",
    "CVE-2023-32390",
    "CVE-2023-32391",
    "CVE-2023-32392",
    "CVE-2023-32394",
    "CVE-2023-32395",
    "CVE-2023-32397",
    "CVE-2023-32398",
    "CVE-2023-32399",
    "CVE-2023-32400",
    "CVE-2023-32401",
    "CVE-2023-32402",
    "CVE-2023-32403",
    "CVE-2023-32404",
    "CVE-2023-32405",
    "CVE-2023-32407",
    "CVE-2023-32408",
    "CVE-2023-32409",
    "CVE-2023-32410",
    "CVE-2023-32411",
    "CVE-2023-32412",
    "CVE-2023-32413",
    "CVE-2023-32414",
    "CVE-2023-32415",
    "CVE-2023-32417",
    "CVE-2023-32420",
    "CVE-2023-32422",
    "CVE-2023-32423",
    "CVE-2023-32428",
    "CVE-2023-32432",
    "CVE-2023-32437",
    "CVE-2023-34352",
    "CVE-2023-42869",
    "CVE-2023-42958"
  );
  script_xref(name:"APPLE-SA", value:"HT213758");
  script_xref(name:"IAVA", value:"2023-A-0264-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");

  script_name(english:"macOS 13.x < 13.4 Multiple Vulnerabilities (HT213758)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.4. It is, therefore, affected by
multiple vulnerabilities:

  - In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-
    provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append
    arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected
    versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a
    -- argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
    (CVE-2023-22809)

  - A type confusion issue was addressed with improved checks. This issue is fixed in iOS 16.5 and iPadOS
    16.5, watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to execute arbitrary code with kernel
    privileges. (CVE-2023-27930)

  - The issue was addressed with additional permissions checks. This issue is fixed in iOS 15.7.6 and iPadOS
    15.7.6, macOS Monterey 12.6.6, macOS Ventura 13.4. A sandboxed app may be able to observe system-wide
    network connections. (CVE-2023-27940)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    9.5, tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5.
    An app may be able to bypass Privacy preferences. (CVE-2023-28191)

  - This issue was addressed with improved state management. This issue is fixed in iOS 16.5 and iPadOS 16.5,
    watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app firewall setting may not take effect after exiting the
    Settings app. (CVE-2023-28202)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, Safari 16.5, iOS 16.5 and iPadOS 16.5.
    Processing web content may disclose sensitive information. Apple is aware of a report that this issue may
    have been actively exploited. (CVE-2023-28204)

  - An issue was discovered in libxml2 before 2.10.4. When hashing empty dict strings in a crafted XML
    document, xmlDictComputeFastKey in dict.c can produce non-deterministic values, leading to various logic
    and memory errors, such as a double free. This behavior occurs because there is an attempt to use the
    first byte of an empty string, and any value is possible (not solely the '\0' value). (CVE-2023-29469)

  - A logic issue was addressed with improved checks. This issue is fixed in watchOS 9.5, macOS Ventura 13.4,
    macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app may bypass Gatekeeper
    checks. (CVE-2023-32352)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7.7,
    macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to modify protected parts of the file
    system. (CVE-2023-32355, CVE-2023-32369, CVE-2023-32395)

  - An authorization issue was addressed with improved state management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An
    app may be able to retain access to system configuration files even after its permission is revoked.
    (CVE-2023-32357)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An unauthenticated user may be able to access recently
    printed documents. (CVE-2023-32360)

  - A permissions issue was addressed by removing vulnerable code and adding additional checks. This issue is
    fixed in macOS Ventura 13.4. An app may be able to bypass Privacy preferences. (CVE-2023-32363)

  - This issue was addressed with improved entitlements. This issue is fixed in iOS 16.5 and iPadOS 16.5,
    macOS Ventura 13.4. An app may be able to access user-sensitive data. (CVE-2023-32367)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. Processing a 3D model may
    result in disclosure of process memory. (CVE-2023-32368)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.5 and iPadOS 16.5, macOS
    Ventura 13.4. An app may be able to break out of its sandbox. (CVE-2023-32371)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 16.5 and
    iPadOS 16.5, watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. Processing an image may result in disclosure of
    process memory. (CVE-2023-32372)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, Safari 16.5, iOS 16.5 and iPadOS 16.5.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited. (CVE-2023-32373)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Monterey
    12.6.6, macOS Ventura 13.4. Processing a 3D model may result in disclosure of process memory.
    (CVE-2023-32375)

  - This issue was addressed with improved entitlements. This issue is fixed in iOS 16.5 and iPadOS 16.5,
    watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to modify protected parts of the file
    system. (CVE-2023-32376)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Ventura
    13.4. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-32379)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Big
    Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. Processing a 3D model may lead to arbitrary code
    execution. (CVE-2023-32380)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. Processing a 3D model may result in disclosure of
    process memory. (CVE-2023-32382)

  - This issue was addressed by forcing hardened runtime on the affected binaries at the system level. This
    issue is fixed in macOS Monterey 12.6.6, macOS Big Sur 11.7.7, macOS Ventura 13.4. An app may be able to
    inject code into sensitive binaries bundled with Xcode. (CVE-2023-32383)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in watchOS 9.5, tvOS
    16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS
    16.5 and iPadOS 16.5. Processing an image may lead to arbitrary code execution. (CVE-2023-32384)

  - A denial-of-service issue was addressed with improved memory handling. This issue is fixed in iOS 16.5 and
    iPadOS 16.5, macOS Ventura 13.4. Opening a PDF file may lead to unexpected app termination.
    (CVE-2023-32385)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS Big
    Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to observe unprotected user
    data. (CVE-2023-32386)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. A remote attacker may be able to cause unexpected app
    termination or arbitrary code execution. (CVE-2023-32387)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    watchOS 9.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey
    12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to bypass Privacy preferences. (CVE-2023-32388)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS 16.5
    and iPadOS 16.5, watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to disclose kernel memory.
    (CVE-2023-32389)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.5 and iPadOS 16.5, watchOS
    9.5, macOS Ventura 13.4. Photos belonging to the Hidden Photos Album could be viewed without
    authentication through Visual Lookup. (CVE-2023-32390)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.6 and iPadOS 15.7.6, watchOS
    9.5, iOS 16.5 and iPadOS 16.5, macOS Ventura 13.4. A shortcut may be able to use sensitive data with
    certain actions without prompting the user. (CVE-2023-32391)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    watchOS 9.5, tvOS 16.5, macOS Ventura 13.4, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and
    iPadOS 16.5. An app may be able to read sensitive location information. (CVE-2023-32392)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.5 and iPadOS 16.5, watchOS
    9.5, tvOS 16.5, macOS Ventura 13.4. A person with physical access to a device may be able to view contact
    information from the lock screen. (CVE-2023-32394)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.7.6 and iPadOS
    15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to modify
    protected parts of the file system. (CVE-2023-32397)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6,
    iOS 16.5 and iPadOS 16.5. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-32398)

  - The issue was addressed with improved handling of caches. This issue is fixed in iOS 16.5 and iPadOS 16.5,
    watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to read sensitive location information.
    (CVE-2023-32399)

  - This issue was addressed with improved checks. This issue is fixed in iOS 16.5 and iPadOS 16.5, watchOS
    9.5, macOS Ventura 13.4. Entitlements and privacy permissions granted to this app may be used by a
    malicious app. (CVE-2023-32400)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in macOS Monterey
    12.6.6, macOS Big Sur 11.7.7, macOS Ventura 13.4. Parsing an office document may lead to an unexpected app
    termination or arbitrary code execution. (CVE-2023-32401)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, Safari 16.5, iOS 16.5 and iPadOS 16.5. Processing web content may disclose
    sensitive information. (CVE-2023-32402)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    9.5, tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey
    12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to read sensitive location information.
    (CVE-2023-32403)

  - This issue was addressed with improved entitlements. This issue is fixed in iOS 16.5 and iPadOS 16.5,
    watchOS 9.5, macOS Ventura 13.4. An app may be able to bypass Privacy preferences. (CVE-2023-32404)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.7.7, macOS
    Monterey 12.6.6, macOS Ventura 13.4. An app may be able to gain root privileges. (CVE-2023-32405)

  - A logic issue was addressed with improved state management. This issue is fixed in watchOS 9.5, tvOS 16.5,
    macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5
    and iPadOS 16.5. An app may be able to bypass Privacy preferences. (CVE-2023-32407)

  - The issue was addressed with improved handling of caches. This issue is fixed in watchOS 9.5, tvOS 16.5,
    macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app
    may be able to read sensitive location information. (CVE-2023-32408)

  - The issue was addressed with improved bounds checks. This issue is fixed in watchOS 9.5, tvOS 16.5, macOS
    Ventura 13.4, iOS 15.7.8 and iPadOS 15.7.8, Safari 16.5, iOS 16.5 and iPadOS 16.5. A remote attacker may
    be able to break out of Web Content sandbox. Apple is aware of a report that this issue may have been
    actively exploited. (CVE-2023-32409)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 15.7.6 and
    iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An app may be able to leak
    sensitive kernel state. (CVE-2023-32410)

  - This issue was addressed with improved entitlements. This issue is fixed in tvOS 16.5, macOS Ventura 13.4,
    macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS 16.5 and iPadOS 16.5. An app may be able to bypass
    Privacy preferences. (CVE-2023-32411)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6,
    iOS 16.5 and iPadOS 16.5. A remote attacker may be able to cause unexpected app termination or arbitrary
    code execution. (CVE-2023-32412)

  - A race condition was addressed with improved state handling. This issue is fixed in watchOS 9.5, tvOS
    16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, macOS Big Sur 11.7.7, macOS Monterey 12.6.6, iOS
    16.5 and iPadOS 16.5. An app may be able to gain root privileges. (CVE-2023-32413)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.4. An app may be
    able to break out of its sandbox. (CVE-2023-32414)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS 16.5
    and iPadOS 16.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to read sensitive location information.
    (CVE-2023-32415)

  - This issue was addressed by restricting options offered on a locked device. This issue is fixed in watchOS
    9.5. An attacker with physical access to a locked Apple Watch may be able to view user photos or contacts
    via accessibility features. (CVE-2023-32417)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 16.5 and
    iPadOS 16.5, watchOS 9.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to cause unexpected system
    termination or read kernel memory. (CVE-2023-32420)

  - This issue was addressed by adding additional SQLite logging restrictions. This issue is fixed in iOS 16.5
    and iPadOS 16.5, tvOS 16.5, macOS Ventura 13.4. An app may be able to bypass Privacy preferences.
    (CVE-2023-32422)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, Safari 16.5, iOS 16.5 and iPadOS 16.5. Processing web content may disclose
    sensitive information. (CVE-2023-32423)

  - This issue was addressed with improved file handling. This issue is fixed in macOS Ventura 13.4, tvOS
    16.5, iOS 16.5 and iPadOS 16.5, watchOS 9.5. An app may be able to gain root privileges. (CVE-2023-32428)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS
    Ventura 13.4, tvOS 16.5, iOS 16.5 and iPadOS 16.5, watchOS 9.5. An app may be able to access user-
    sensitive data. (CVE-2023-32432)

  - The issue was addressed with improvements to the file handling protocol. This issue is fixed in iOS 16.6
    and iPadOS 16.6. An app may be able to break out of its sandbox. (CVE-2023-32437)

  - A permissions issue was addressed with improved redaction of sensitive information. This issue is fixed in
    macOS Ventura 13.4, tvOS 16.5, iOS 16.5 and iPadOS 16.5, watchOS 9.5. An attacker may be able to leak user
    account emails. (CVE-2023-34352)

  - Multiple memory corruption issues were addressed with improved input validation. This issue is fixed in
    macOS Ventura 13.4, iOS 16.5 and iPadOS 16.5. Multiple issues in libxml2. (CVE-2023-42869)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Ventura 13.4.
    An app may be able to gain elevated privileges. (CVE-2023-42958)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213758");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32412");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudoedit Extra Arguments Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
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
  { 'fixed_version' : '13.4.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.4' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
