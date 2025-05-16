#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156230);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id(
    "CVE-2021-30767",
    "CVE-2021-30926",
    "CVE-2021-30927",
    "CVE-2021-30929",
    "CVE-2021-30934",
    "CVE-2021-30935",
    "CVE-2021-30936",
    "CVE-2021-30937",
    "CVE-2021-30938",
    "CVE-2021-30939",
    "CVE-2021-30940",
    "CVE-2021-30941",
    "CVE-2021-30942",
    "CVE-2021-30943",
    "CVE-2021-30944",
    "CVE-2021-30945",
    "CVE-2021-30946",
    "CVE-2021-30947",
    "CVE-2021-30949",
    "CVE-2021-30950",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30955",
    "CVE-2021-30957",
    "CVE-2021-30958",
    "CVE-2021-30960",
    "CVE-2021-30964",
    "CVE-2021-30965",
    "CVE-2021-30966",
    "CVE-2021-30968",
    "CVE-2021-30970",
    "CVE-2021-30971",
    "CVE-2021-30972",
    "CVE-2021-30973",
    "CVE-2021-30975",
    "CVE-2021-30976",
    "CVE-2021-30977",
    "CVE-2021-30979",
    "CVE-2021-30980",
    "CVE-2021-30981",
    "CVE-2021-30982",
    "CVE-2021-30984",
    "CVE-2021-30986",
    "CVE-2021-30987",
    "CVE-2021-30990",
    "CVE-2021-30993",
    "CVE-2021-30995",
    "CVE-2021-30996",
    "CVE-2021-31000",
    "CVE-2021-31007",
    "CVE-2021-31009",
    "CVE-2021-31013"
  );
  script_xref(name:"APPLE-SA", value:"HT212978");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-12-15-2");
  script_xref(name:"IAVA", value:"2021-A-0577-S");

  script_name(english:"macOS 12.x < 12.1 Multiple Vulnerabilities (HT212978)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.1. It is, therefore, affected by
multiple vulnerabilities:

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Monterey
    12.1. A device may be passively tracked via BSSIDs. (CVE-2021-30987)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.1,
    Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. A malicious application may bypass Gatekeeper
    checks. (CVE-2021-30950, CVE-2021-30976)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. Parsing a maliciously crafted audio file may lead
    to disclosure of user information. (CVE-2021-30960)

  - A device configuration issue was addressed with an updated configuration. This issue is fixed in macOS
    Monterey 12.1. A device may be passively tracked by its Bluetooth MAC address. (CVE-2021-30986)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.1,
    watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. User traffic might unexpectedly be leaked to a proxy
    server despite PAC configurations. (CVE-2021-30966)

  - Description: A memory corruption issue in the processing of ICC profiles was addressed with improved input
    validation. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2.
    Processing a maliciously crafted image may lead to arbitrary code execution. (CVE-2021-30926)

  - Description: A memory corruption issue in the processing of ICC profiles was addressed with improved input
    validation. This issue is fixed in macOS Big Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update
    2021-008 Catalina, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing a maliciously crafted image may lead
    to arbitrary code execution. (CVE-2021-30942)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. Processing a maliciously crafted audio file may
    lead to arbitrary code execution. (CVE-2021-30957)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Big Sur
    11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2,
    watchOS 8.3. Playing a malicious audio file may lead to arbitrary code execution. (CVE-2021-30958)

  - A logic issue was addressed with improved validation. This issue is fixed in Security Update 2021-008
    Catalina, macOS Big Sur 11.6.2. An application may be able to execute arbitrary code with kernel
    privileges. (CVE-2021-30935)

  - This issue was addressed with improved checks. This issue is fixed in macOS Big Sur 11.6.2, tvOS 15.2,
    macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2, watchOS 8.3. A local
    attacker may be able to elevate their privileges. (CVE-2021-30945)

  - Description: A permissions issue was addressed with improved validation. This issue is fixed in iOS 15.1
    and iPadOS 15.1, tvOS 15.1, macOS Big Sur 11.6.2, watchOS 8.1, macOS Monterey 12.1. A malicious
    application may be able to bypass Privacy preferences. (CVE-2021-31007)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Monterey
    12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2. Processing a maliciously crafted font may result in
    the disclosure of process memory. (CVE-2021-31013)

  - A permissions issue was addressed with improved validation. This issue is fixed in iOS 15.2 and iPadOS
    15.2, watchOS 8.3, macOS Monterey 12.1, tvOS 15.2. A malicious application may be able to read sensitive
    contact information. (CVE-2021-31000)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in macOS Monterey 12.1,
    Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. A malicious application may be able to execute
    arbitrary code with kernel privileges. (CVE-2021-30977)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Big Sur
    11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2,
    watchOS 8.3. Processing a maliciously crafted image may lead to arbitrary code execution. (CVE-2021-30939)

  - A buffer overflow was addressed with improved bounds checking. This issue is fixed in macOS Monterey 12.1,
    Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. An application may be able to execute arbitrary
    code with kernel privileges. (CVE-2021-30981)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1,
    iOS 15.2 and iPadOS 15.2. A malicious application may be able to execute arbitrary code with kernel
    privileges. (CVE-2021-30996)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Monterey 12.1, Security
    Update 2021-008 Catalina, macOS Big Sur 11.6.2. A remote attacker may be able to cause unexpected
    application termination or heap corruption. (CVE-2021-30982)

  - A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS Big
    Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2,
    watchOS 8.3. A malicious application may be able to execute arbitrary code with kernel privileges.
    (CVE-2021-30937)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2,
    watchOS 8.3. An application may be able to execute arbitrary code with kernel privileges. (CVE-2021-30927,
    CVE-2021-30980)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Big
    Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2,
    watchOS 8.3. A malicious application may be able to execute arbitrary code with kernel privileges.
    (CVE-2021-30949)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. An attacker in a privileged network position may
    be able to execute arbitrary code. (CVE-2021-30993)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1,
    watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary
    code with kernel privileges. (CVE-2021-30955)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Monterey 12.1, Security
    Update 2021-008 Catalina, macOS Big Sur 11.6.2. A malicious application may bypass Gatekeeper checks.
    (CVE-2021-30990)

  - An issue in the handling of group membership was resolved with improved logic. This issue is fixed in iOS
    15.2 and iPadOS 15.2, watchOS 8.3, macOS Monterey 12.1. A malicious user may be able to leave a messages
    group but continue to receive messages in that group. (CVE-2021-30943)

  - Multiple issues were addressed by removing HDF5. This issue is fixed in iOS 15.2 and iPadOS 15.2, macOS
    Monterey 12.1. Multiple issues in HDF5. (CVE-2021-31009)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS
    Monterey 12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2, Security Update 2021-008 Catalina.
    Processing a maliciously crafted USD file may lead to unexpected application termination or arbitrary code
    execution. (CVE-2021-30971)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Monterey
    12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2, Security Update 2021-008 Catalina. Processing a
    maliciously crafted file may disclose user information. (CVE-2021-30973)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS
    Monterey 12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2, Security Update 2021-008 Catalina.
    Processing a maliciously crafted USD file may disclose memory contents. (CVE-2021-30929)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2, Security Update 2021-008 Catalina. Processing a
    maliciously crafted USD file may lead to unexpected application termination or arbitrary code execution.
    (CVE-2021-30979)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.1, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2, Security Update 2021-008 Catalina. Processing a
    maliciously crafted USD file may disclose memory contents. (CVE-2021-30940, CVE-2021-30941)

  - A race condition was addressed with improved state handling. This issue is fixed in macOS Big Sur 11.6.2,
    tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2, watchOS 8.3.
    A malicious application may be able to elevate privileges. (CVE-2021-30995)

  - A validation issue related to hard link behavior was addressed with improved sandbox restrictions. This
    issue is fixed in macOS Big Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, Security Update 2021-008 Catalina,
    iOS 15.2 and iPadOS 15.2, watchOS 8.3. A malicious application may be able to bypass certain Privacy
    preferences. (CVE-2021-30968)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.1,
    watchOS 8.3, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2. A malicious application may be able to bypass
    certain Privacy preferences. (CVE-2021-30946)

  - An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Big Sur
    11.6.2, tvOS 15.2, macOS Monterey 12.1, iOS 15.2 and iPadOS 15.2, watchOS 8.3. An application may be able
    to access a user's files. (CVE-2021-30947)

  - This issue was addressed by disabling execution of JavaScript when viewing a scripting dictionary. This
    issue is fixed in macOS Monterey 12.1, Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. A
    malicious OSAX scripting addition may bypass Gatekeeper checks and circumvent sandbox restrictions.
    (CVE-2021-30975)

  - Description: A logic issue was addressed with improved state management. This issue is fixed in iOS 15.2
    and iPadOS 15.2, watchOS 8.3, macOS Monterey 12.1, tvOS 15.2. A malicious app may be able to access data
    from other apps by enabling additional logging. (CVE-2021-30944)

  - This issue was addressed with improved checks. This issue is fixed in Security Update 2022-001 Catalina,
    macOS Big Sur 11.6.3. A malicious application may be able to bypass certain Privacy preferences.
    (CVE-2021-30972)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.6.2,
    macOS Monterey 12.1, Security Update 2021-008 Catalina, iOS 15.2 and iPadOS 15.2, watchOS 8.3. A local
    user may be able to modify protected parts of the file system. (CVE-2021-30767)

  - An inherited permissions issue was addressed with additional restrictions. This issue is fixed in macOS
    Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2. A malicious application may be able to bypass
    Privacy preferences. (CVE-2021-30964)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.1,
    macOS Big Sur 11.6.2. A malicious application may be able to bypass Privacy preferences. (CVE-2021-30970)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.1,
    Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. A malicious application may be able to cause a
    denial of service to Endpoint Security clients. (CVE-2021-30965)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30934)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30936, CVE-2021-30951)

  - An integer overflow was addressed with improved input validation. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30952)

  - A race condition was addressed with improved state handling. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30984)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in tvOS 15.2, macOS
    Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2021-30953)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in tvOS 15.2,
    macOS Monterey 12.1, Safari 15.2, iOS 15.2 and iPadOS 15.2, watchOS 8.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30954)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.1, Security Update
    2021-008 Catalina, macOS Big Sur 11.6.2. A local user may be able to cause unexpected system termination
    or read kernel memory. (CVE-2021-30938)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212978");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30981");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31009");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '12.1.0', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
