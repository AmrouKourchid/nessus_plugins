#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189302);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id(
    "CVE-2024-23201",
    "CVE-2024-23203",
    "CVE-2024-23204",
    "CVE-2024-23206",
    "CVE-2024-23207",
    "CVE-2024-23208",
    "CVE-2024-23209",
    "CVE-2024-23210",
    "CVE-2024-23211",
    "CVE-2024-23212",
    "CVE-2024-23213",
    "CVE-2024-23214",
    "CVE-2024-23215",
    "CVE-2024-23217",
    "CVE-2024-23218",
    "CVE-2024-23222",
    "CVE-2024-23223",
    "CVE-2024-23224",
    "CVE-2024-23271",
    "CVE-2024-27791"
  );
  script_xref(name:"APPLE-SA", value:"HT214061");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/13");
  script_xref(name:"IAVA", value:"2024-A-0050-S");
  script_xref(name:"IAVA", value:"2024-A-0142-S");

  script_name(english:"macOS 14.x < 14.3 Multiple Vulnerabilities (HT214061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.3. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 10.3, tvOS 17.3, iOS
    17.3 and iPadOS 17.3, macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, macOS Ventura 13.6.4, macOS
    Monterey 12.7.3. An app may be able to execute arbitrary code with kernel privileges. (CVE-2024-23212)

  - A timing side-channel issue was addressed with improvements to constant-time computation in cryptographic
    functions. This issue is fixed in macOS Sonoma 14.3, watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An
    attacker may be able to decrypt legacy RSA PKCS#1 v1.5 ciphertexts without having the private key.
    (CVE-2024-23218)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.3, macOS Ventura
    13.6.4. An app may be able to access sensitive user data. (CVE-2024-23224)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.3, watchOS
    10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An app may be able to execute arbitrary code with kernel
    privileges. (CVE-2024-23208)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Monterey
    12.7.4, watchOS 10.3, tvOS 17.3, macOS Ventura 13.6.5, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3. An app
    may be able to cause a denial-of-service. (CVE-2024-23201)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.3.
    Processing web content may lead to arbitrary code execution. (CVE-2024-23209)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in watchOS
    10.3, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, macOS Ventura 13.6.4, macOS Monterey 12.7.3. An app may
    be able to access sensitive user data. (CVE-2024-23207)

  - A privacy issue was addressed with improved handling of files. This issue is fixed in macOS Sonoma 14.3,
    watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An app may be able to access sensitive user data.
    (CVE-2024-23223)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS 17.3, tvOS 17.3,
    macOS Ventura 13.6.4, iOS 16.7.5 and iPadOS 16.7.5, macOS Monterey 12.7.3, macOS Sonoma 14.3. An app may
    be able to corrupt coprocessor memory. (CVE-2024-27791)

  - A privacy issue was addressed with improved handling of user preferences. This issue is fixed in watchOS
    10.3, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, Safari 17.3. A user's
    private browsing activity may be visible in Settings. (CVE-2024-23211)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Sonoma 14.3, iOS
    17.3 and iPadOS 17.3. A shortcut may be able to use sensitive data with certain actions without prompting
    the user. (CVE-2024-23203)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Sonoma 14.3,
    watchOS 10.3, iOS 17.3 and iPadOS 17.3. A shortcut may be able to use sensitive data with certain actions
    without prompting the user. (CVE-2024-23204)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS
    Sonoma 14.3, watchOS 10.3, iOS 17.3 and iPadOS 17.3. An app may be able to bypass certain Privacy
    preferences. (CVE-2024-23217)

  - An issue was addressed with improved handling of temporary files. This issue is fixed in macOS Sonoma
    14.3, watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An app may be able to access user-sensitive data.
    (CVE-2024-23215)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.3, watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An app may be able to view a user's phone
    number in system logs. (CVE-2024-23210)

  - An access issue was addressed with improved access restrictions. This issue is fixed in watchOS 10.3, tvOS
    17.3, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, Safari 17.3. A
    maliciously crafted webpage may be able to fingerprint the user. (CVE-2024-23206)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 10.3, tvOS 17.3, iOS
    17.3 and iPadOS 17.3, macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, Safari 17.3. Processing web content
    may lead to arbitrary code execution. (CVE-2024-23213)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    macOS Sonoma 14.3, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2024-23214)

  - A type confusion issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS
    17.3, macOS Sonoma 14.3, tvOS 17.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been exploited. (CVE-2024-23222)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS 17.3, Safari
    17.3, tvOS 17.3, macOS Sonoma 14.3, watchOS 10.3. A malicious website may cause unexpected cross-origin
    behavior. (CVE-2024-23271)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214061");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23222");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
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
  { 'fixed_version' : '14.3.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.3' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
