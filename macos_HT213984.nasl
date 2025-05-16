#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189369);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/07");

  script_cve_id(
    "CVE-2023-28826",
    "CVE-2023-30774",
    "CVE-2023-36191",
    "CVE-2023-38403",
    "CVE-2023-40404",
    "CVE-2023-40405",
    "CVE-2023-40408",
    "CVE-2023-40413",
    "CVE-2023-40416",
    "CVE-2023-40421",
    "CVE-2023-40423",
    "CVE-2023-40444",
    "CVE-2023-40446",
    "CVE-2023-40447",
    "CVE-2023-40449",
    "CVE-2023-41072",
    "CVE-2023-41254",
    "CVE-2023-41975",
    "CVE-2023-41976",
    "CVE-2023-41977",
    "CVE-2023-41982",
    "CVE-2023-41983",
    "CVE-2023-41988",
    "CVE-2023-41989",
    "CVE-2023-41997",
    "CVE-2023-42438",
    "CVE-2023-42823",
    "CVE-2023-42834",
    "CVE-2023-42835",
    "CVE-2023-42836",
    "CVE-2023-42838",
    "CVE-2023-42839",
    "CVE-2023-42840",
    "CVE-2023-42841",
    "CVE-2023-42842",
    "CVE-2023-42843",
    "CVE-2023-42844",
    "CVE-2023-42845",
    "CVE-2023-42847",
    "CVE-2023-42848",
    "CVE-2023-42849",
    "CVE-2023-42850",
    "CVE-2023-42852",
    "CVE-2023-42853",
    "CVE-2023-42854",
    "CVE-2023-42856",
    "CVE-2023-42857",
    "CVE-2023-42858",
    "CVE-2023-42859",
    "CVE-2023-42860",
    "CVE-2023-42861",
    "CVE-2023-42873",
    "CVE-2023-42877",
    "CVE-2023-42878",
    "CVE-2023-42889",
    "CVE-2023-42935",
    "CVE-2023-42942",
    "CVE-2023-42945",
    "CVE-2023-42946",
    "CVE-2023-42952",
    "CVE-2023-42953",
    "CVE-2023-4733",
    "CVE-2023-4734",
    "CVE-2023-4735",
    "CVE-2023-4736",
    "CVE-2023-4738",
    "CVE-2023-4750",
    "CVE-2023-4751",
    "CVE-2023-4752",
    "CVE-2023-4781"
  );
  script_xref(name:"APPLE-SA", value:"HT213984");
  script_xref(name:"IAVA", value:"2024-A-0050-S");
  script_xref(name:"IAVA", value:"2024-A-0142-S");
  script_xref(name:"IAVA", value:"2024-A-0179-S");
  script_xref(name:"IAVA", value:"2024-A-0275-S");

  script_name(english:"macOS 14.x < 14.1 Multiple Vulnerabilities (HT213984)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.1. It is, therefore, affected by
multiple vulnerabilities:

  - A vulnerability was found in the libtiff library. This flaw causes a heap buffer overflow issue via the
    TIFFTAG_INKNAMES and TIFFTAG_NUMBEROFINKS values. (CVE-2023-30774)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1.
    An app may be able to access user-sensitive data. (CVE-2023-40444)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, macOS
    Ventura 13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.1. An app with root privileges may be able to
    access private information. (CVE-2023-42952)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1.
    An app may gain unauthorized access to Bluetooth. (CVE-2023-42945)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.1, iOS 17.1 and iPadOS 17.1. An app may be able to access sensitive user data.
    (CVE-2023-41072, CVE-2023-42857)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. An app may
    be able to cause a denial-of-service. (CVE-2023-40449)

  - The issue was resolved by sanitizing logging This issue is fixed in watchOS 10.1, macOS Sonoma 14.1, tvOS
    17.1, macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1.
    An app may be able to access user-sensitive data. (CVE-2023-42823)

  - The issue was addressed by restricting options offered on a locked device. This issue is fixed in macOS
    Sonoma 14.1. An attacker may be able to execute arbitrary code as root from the Lock Screen.
    (CVE-2023-41989)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to cause a denial-of-service to Endpoint
    Security clients. (CVE-2023-42854)

  - The issue was addressed with improved handling of caches. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma
    14.1. An app may be able to read sensitive location information. (CVE-2023-40413)

  - A privacy issue was addressed with improved handling of files. This issue is fixed in watchOS 10.1, macOS
    Sonoma 14.1, macOS Monterey 12.7.2, macOS Ventura 13.6.3, iOS 17.1 and iPadOS 17.1. An app may be able to
    access sensitive user data. (CVE-2023-42834)

  - This issue was addressed with improved handling of symlinks. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. A website may be able to access sensitive user data when
    resolving symlinks. (CVE-2023-42844)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in tvOS 17.1, watchOS
    10.1, macOS Sonoma 14.1, iOS 17.1 and iPadOS 17.1. An app may be able to access sensitive user data.
    (CVE-2023-42953)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. Processing
    an image may result in disclosure of process memory. (CVE-2023-40416)

  - The issue was addressed with improved bounds checks. This issue is fixed in watchOS 10.1, macOS Sonoma
    14.1, tvOS 17.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1. Processing
    a maliciously crafted image may lead to heap corruption. (CVE-2023-42848)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma 14.1. An app may
    be able to execute arbitrary code with kernel privileges. (CVE-2023-40423)

  - iperf3 before 3.14 allows peers to cause an integer overflow and heap corruption via a crafted length
    field. (CVE-2023-38403)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    macOS Monterey 12.7.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma
    14.1. An attacker that has already achieved kernel code execution may be able to bypass kernel memory
    mitigations. (CVE-2023-42849)

  - The issue was addressed with improved permissions logic. This issue is fixed in macOS Sonoma 14.1. An app
    may be able to access sensitive user data. (CVE-2023-42850)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.1, iOS
    16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Processing maliciously crafted input may lead to
    arbitrary code execution in user-installed apps. (CVE-2023-40446)

  - This issue was addressed with improved handling of symlinks. This issue is fixed in watchOS 10.1, macOS
    Sonoma 14.1, tvOS 17.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1. A
    malicious app may be able to gain root privileges. (CVE-2023-42942)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Sonoma 14.1. An
    attacker with knowledge of a standard user's credentials can unlock another standard user's locked screen
    on the same Mac. (CVE-2023-42861)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Ventura
    13.6.4. A local attacker may be able to view the previous logged in user's desktop from the fast user
    switching screen. (CVE-2023-42935)

  - An inconsistent user interface issue was addressed with improved state management. This issue is fixed in
    macOS Sonoma 14.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Hide My Email may
    be deactivated unexpectedly. (CVE-2023-40408)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.1. An app may be able to read sensitive location information. (CVE-2023-40405)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS
    16.7.6 and iPadOS 16.7.6, macOS Monterey 12.7.4, macOS Sonoma 14.1, macOS Ventura 13.6.5. An app may be
    able to access sensitive user data. (CVE-2023-28826)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. Processing a file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2023-42856)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sonoma
    14.1. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-40404)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to modify protected parts of the file system.
    (CVE-2023-42859, CVE-2023-42877)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to access user-sensitive data. (CVE-2023-42840,
    CVE-2023-42858)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to access user-sensitive data. (CVE-2023-42853)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to modify protected parts of the file
    system. (CVE-2023-42860)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to bypass certain Privacy preferences. (CVE-2023-42889)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, iOS 17.1 and
    iPadOS 17.1. An attacker may be able to access passkeys without authentication. (CVE-2023-42847)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.1, iOS 17.1 and iPadOS 17.1. Photos in the Hidden Photos Album may be viewed without authentication.
    (CVE-2023-42845)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, iOS 17.1
    and iPadOS 17.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1. An app may be able to execute
    arbitrary code with kernel privileges. (CVE-2023-42841)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Sonoma 14.1, tvOS 17.1,
    macOS Monterey 12.7.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, macOS Ventura 13.6.1. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2023-42873)

  - An access issue was addressed with improvements to the sandbox. This issue is fixed in macOS Ventura
    13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.2. An app may be able to execute arbitrary code out of its
    sandbox or with certain elevated privileges. (CVE-2023-42838)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1. An attacker
    may be able to access user data. (CVE-2023-42835)

  - The issue was addressed with improved handling of caches. This issue is fixed in macOS Sonoma 14.1, iOS
    16.7.2 and iPadOS 16.7.2. Visiting a malicious website may reveal browsing history. (CVE-2023-41977)

  - An inconsistent user interface issue was addressed with improved state management. This issue is fixed in
    macOS Sonoma 14.1. Visiting a malicious website may lead to user interface spoofing. (CVE-2023-42438)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, macOS
    Ventura 13.6.3, macOS Sonoma 14.1, macOS Monterey 12.7.2. An attacker may be able to access connected
    network volumes mounted in the home directory. (CVE-2023-42836)

  - This issue was addressed with improved state management. This issue is fixed in tvOS 17.1, watchOS 10.1,
    macOS Sonoma 14.1, iOS 17.1 and iPadOS 17.1. An app may be able to access sensitive user data.
    (CVE-2023-42839)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    watchOS 10.1, macOS Sonoma 14.1, iOS 17.1 and iPadOS 17.1. An app may be able to access sensitive user
    data. (CVE-2023-42878)

  - This issue was addressed by restricting options offered on a locked device. This issue is fixed in macOS
    Sonoma 14.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. An attacker with
    physical access may be able to use Siri to access sensitive user data. (CVE-2023-41982, CVE-2023-41997)

  - This issue was addressed by restricting options offered on a locked device. This issue is fixed in macOS
    Sonoma 14.1, watchOS 10.1, iOS 17.1 and iPadOS 17.1. An attacker with physical access may be able to use
    Siri to access sensitive user data. (CVE-2023-41988)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in tvOS
    17.1, watchOS 10.1, macOS Sonoma 14.1, iOS 17.1 and iPadOS 17.1. An app may be able to leak sensitive user
    information. (CVE-2023-42946)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn
    by its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2023-36191)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.1,
    macOS Monterey 12.7.1, macOS Ventura 13.6.1. An app may be able to access sensitive user data.
    (CVE-2023-40421)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1. An app may be able
    to access sensitive user data. (CVE-2023-42842)

  - Use After Free in GitHub repository vim/vim prior to 9.0.1840. (CVE-2023-4733)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.1846. (CVE-2023-4734)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1847. (CVE-2023-4735)

  - Untrusted Search Path in GitHub repository vim/vim prior to 9.0.1833. (CVE-2023-4736)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1848. (CVE-2023-4738)

  - Use After Free in GitHub repository vim/vim prior to 9.0.1857. (CVE-2023-4750)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1331. (CVE-2023-4751)

  - Use After Free in GitHub repository vim/vim prior to 9.0.1858. (CVE-2023-4752)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1873. (CVE-2023-4781)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 17.1 and iPadOS 17.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Ventura 13.6.1, macOS Sonoma
    14.1. An app may be able to access sensitive user data. (CVE-2023-41254)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 17.1 and iPadOS 17.1,
    watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Sonoma 14.1, Safari 17.1, tvOS 17.1. Processing web
    content may lead to arbitrary code execution. (CVE-2023-40447)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17.1 and
    iPadOS 17.1, watchOS 10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Sonoma 14.1, Safari 17.1, tvOS 17.1.
    Processing web content may lead to arbitrary code execution. (CVE-2023-41976)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, watchOS
    10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Sonoma 14.1, Safari 17.1, tvOS 17.1. Processing web content may
    lead to arbitrary code execution. (CVE-2023-42852)

  - An inconsistent user interface issue was addressed with improved state management. This issue is fixed in
    iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, Safari 17.1, macOS Sonoma 14.1. Visiting a
    malicious website may lead to address bar spoofing. (CVE-2023-42843)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, Safari
    17.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Processing web content may lead to a denial-
    of-service. (CVE-2023-41983)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.1, macOS
    Monterey 12.7.1, macOS Ventura 13.6.1. A website may be able to access the microphone without the
    microphone use indicator being shown. (CVE-2023-41975)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213984");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42852");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

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
  { 'fixed_version' : '14.1.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
