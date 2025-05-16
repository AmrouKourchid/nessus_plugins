#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191714);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id(
    "CVE-2023-28826",
    "CVE-2023-40389",
    "CVE-2024-23201",
    "CVE-2024-23204",
    "CVE-2024-23216",
    "CVE-2024-23218",
    "CVE-2024-23225",
    "CVE-2024-23227",
    "CVE-2024-23230",
    "CVE-2024-23234",
    "CVE-2024-23244",
    "CVE-2024-23245",
    "CVE-2024-23247",
    "CVE-2024-23257",
    "CVE-2024-23264",
    "CVE-2024-23265",
    "CVE-2024-23266",
    "CVE-2024-23267",
    "CVE-2024-23268",
    "CVE-2024-23269",
    "CVE-2024-23270",
    "CVE-2024-23272",
    "CVE-2024-23274",
    "CVE-2024-23275",
    "CVE-2024-23276",
    "CVE-2024-23283",
    "CVE-2024-23286",
    "CVE-2024-23299"
  );
  script_xref(name:"APPLE-SA", value:"HT214083");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/27");
  script_xref(name:"IAVA", value:"2024-A-0142-S");
  script_xref(name:"IAVA", value:"2024-A-0275-S");

  script_name(english:"macOS 12.x < 12.7.4 Multiple Vulnerabilities (HT214083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.4. It is, therefore, affected by
multiple vulnerabilities:

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS
    16.7.6 and iPadOS 16.7.6, macOS Monterey 12.7.4, macOS Sonoma 14.1, macOS Ventura 13.6.5. An app may be
    able to access sensitive user data. (CVE-2023-28826)

  - The issue was addressed with improved restriction of data container access. This issue is fixed in macOS
    Ventura 13.6.5, macOS Monterey 12.7.4. An app may be able to access sensitive user data. (CVE-2023-40389)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Monterey
    12.7.4, watchOS 10.3, tvOS 17.3, macOS Ventura 13.6.5, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3. An app
    may be able to cause a denial-of-service. (CVE-2024-23201)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Sonoma 14.3,
    watchOS 10.3, iOS 17.3 and iPadOS 17.3. A shortcut may be able to use sensitive data with certain actions
    without prompting the user. (CVE-2024-23204)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Sonoma 14.4,
    macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to overwrite arbitrary files.
    (CVE-2024-23216)

  - A timing side-channel issue was addressed with improvements to constant-time computation in cryptographic
    functions. This issue is fixed in macOS Sonoma 14.3, watchOS 10.3, tvOS 17.3, iOS 17.3 and iPadOS 17.3. An
    attacker may be able to decrypt legacy RSA PKCS#1 v1.5 ciphertexts without having the private key.
    (CVE-2024-23218)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 16.7.6 and
    iPadOS 16.7.6, iOS 17.4 and iPadOS 17.4. An attacker with arbitrary kernel read and write capability may
    be able to bypass kernel memory protections. Apple is aware of a report that this issue may have been
    exploited. (CVE-2024-23225)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to read sensitive location
    information. (CVE-2024-23227)

  - This issue was addressed with improved file handling. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to access sensitive user data. (CVE-2024-23230)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to execute arbitrary code
    with kernel privileges. (CVE-2024-23234)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4. An app from a standard user account may be able to escalate privilege after admin user
    login. (CVE-2024-23244)

  - This issue was addressed by adding an additional prompt for user consent. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. Third-party shortcuts may use a legacy action
    from Automator to send events to apps without user consent. (CVE-2024-23245)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. Processing a file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2024-23247)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.4, macOS
    Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 16.7.6 and iPadOS 16.7.6. Processing an image may
    result in disclosure of process memory. (CVE-2024-23257)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in macOS Monterey
    12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, iOS 16.7.6 and
    iPadOS 16.7.6, tvOS 17.4. An application may be able to read restricted memory. (CVE-2024-23264)

  - A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS
    Monterey 12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS
    10.4, iOS 16.7.6 and iPadOS 16.7.6, tvOS 17.4. An app may be able to cause unexpected system termination
    or write kernel memory. (CVE-2024-23265)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to modify protected parts of the file system.
    (CVE-2024-23266)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to bypass certain Privacy preferences. (CVE-2024-23267)

  - An injection issue was addressed with improved input validation. This issue is fixed in macOS Sonoma 14.4,
    macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to elevate privileges. (CVE-2024-23268,
    CVE-2024-23274)

  - A downgrade issue affecting Intel-based Mac computers was addressed with additional code-signing
    restrictions. This issue is fixed in macOS Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An
    app may be able to modify protected parts of the file system. (CVE-2024-23269)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.4, macOS
    Ventura 13.6.5, macOS Sonoma 14.4, iOS 17.4 and iPadOS 17.4, tvOS 17.4. An app may be able to execute
    arbitrary code with kernel privileges. (CVE-2024-23270)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. A user may gain access to protected parts of the file system.
    (CVE-2024-23272)

  - A race condition was addressed with additional validation. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to access protected user data. (CVE-2024-23275)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to elevate privileges. (CVE-2024-23276)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 16.7.6 and iPadOS 16.7.6, macOS Monterey 12.7.4, macOS Sonoma 14.4, macOS Ventura 13.6.5. An app may
    be able to access user-sensitive data. (CVE-2024-23283)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS
    16.7.6 and iPadOS 16.7.6, tvOS 17.4. Processing an image may lead to arbitrary code execution.
    (CVE-2024-23286)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Ventura
    13.6.5, macOS Monterey 12.7.4. An app may be able to break out of its sandbox. (CVE-2024-23299)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23204");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23299");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
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
  { 'fixed_version' : '12.7.4', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.4' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
