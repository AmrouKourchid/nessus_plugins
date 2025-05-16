#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207227);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2023-52356",
    "CVE-2023-6277",
    "CVE-2024-2004",
    "CVE-2024-23261",
    "CVE-2024-2379",
    "CVE-2024-2398",
    "CVE-2024-2466",
    "CVE-2024-27826",
    "CVE-2024-27873",
    "CVE-2024-27877",
    "CVE-2024-27881",
    "CVE-2024-27882",
    "CVE-2024-27883",
    "CVE-2024-40774",
    "CVE-2024-40775",
    "CVE-2024-40781",
    "CVE-2024-40783",
    "CVE-2024-40784",
    "CVE-2024-40786",
    "CVE-2024-40787",
    "CVE-2024-40788",
    "CVE-2024-40793",
    "CVE-2024-40796",
    "CVE-2024-40798",
    "CVE-2024-40799",
    "CVE-2024-40800",
    "CVE-2024-40802",
    "CVE-2024-40803",
    "CVE-2024-40806",
    "CVE-2024-40807",
    "CVE-2024-40809",
    "CVE-2024-40812",
    "CVE-2024-40815",
    "CVE-2024-40816",
    "CVE-2024-40817",
    "CVE-2024-40818",
    "CVE-2024-40821",
    "CVE-2024-40823",
    "CVE-2024-40827",
    "CVE-2024-40828",
    "CVE-2024-40829",
    "CVE-2024-40833",
    "CVE-2024-40834",
    "CVE-2024-40835",
    "CVE-2024-44205",
    "CVE-2024-6387"
  );
  script_xref(name:"APPLE-SA", value:"120912");
  script_xref(name:"IAVA", value:"2024-A-0578-S");

  script_name(english:"macOS 13.x < 13.6.8 Multiple Vulnerabilities (120912)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.6.8. It is, therefore, affected by
multiple vulnerabilities:

  - A segment fault (SEGV) flaw was found in libtiff that could be triggered by passing a crafted tiff file to
    the TIFFReadRGBATileExt() API. This flaw allows a remote attacker to cause a heap-buffer overflow, leading
    to a denial of service. (CVE-2023-52356)

  - An out-of-memory flaw was found in libtiff. Passing a crafted tiff file to TIFFOpen() API may allow a
    remote attacker to cause a denial of service via a craft input with size smaller than 379 KB.
    (CVE-2023-6277)

  - When a protocol selection parameter option disables all protocols without adding any then the default set
    of protocols would remain in the allowed set due to an error in the logic for removing protocols. The
    below command would perform a request to curl.se with a plaintext protocol which has been explicitly
    disabled. curl --proto -all,-http http://curl.se The flaw is only present if the set of selected protocols
    disables the entire set of available protocols, in itself a command with no practical use and therefore
    unlikely to be encountered in real situations. The curl security team has thus assessed this to be low
    severity bug. (CVE-2024-2004)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.7.6,
    macOS Sonoma 14.4, macOS Ventura 13.6.8. An attacker may be able to read information belonging to another
    user. (CVE-2024-23261)

  - libcurl skips the certificate verification for a QUIC connection under certain conditions, when built to
    use wolfSSL. If told to use an unknown/bad cipher or curve, the error path accidentally skips the
    verification and returns OK, thus ignoring any certificate problems. (CVE-2024-2379)

  - When an application tells libcurl it wants to allow HTTP/2 server push, and the amount of received headers
    for the push surpasses the maximum allowed limit (1000), libcurl aborts the server push. When aborting,
    libcurl inadvertently does not free all the previously allocated headers and instead leaks the memory.
    Further, this error condition fails silently and is therefore not easily detected by an application.
    (CVE-2024-2398)

  - libcurl did not check the server certificate of TLS connections done to a host specified as an IP address,
    when built to use mbedTLS. libcurl would wrongly avoid using the set hostname function when the specified
    hostname was given as an IP address, therefore completely skipping the certificate check. This affects all
    uses of TLS protocols (HTTPS, FTPS, IMAPS, POPS3, SMTPS, etc). (CVE-2024-2466)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.6.8, macOS
    Sonoma 14.5, macOS Monterey 12.7.6, watchOS 10.5, visionOS 1.3, tvOS 17.5, iOS 17.5 and iPadOS 17.5. An
    app may be able to execute arbitrary code with kernel privileges. (CVE-2024-27826)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS
    16.7.9 and iPadOS 16.7.9, macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, macOS
    Sonoma 14.6. Processing a maliciously crafted video file may lead to unexpected app termination.
    (CVE-2024-27873)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.6, macOS
    Monterey 12.7.6, macOS Ventura 13.6.8. Processing a maliciously crafted file may lead to a denial-of-
    service or potentially disclose memory contents. (CVE-2024-27877)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. An app may be able to access information
    about a user's contacts. (CVE-2024-27881)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.6,
    macOS Monterey 12.7.6, macOS Ventura 13.6.8. An app may be able to modify protected parts of the file
    system. (CVE-2024-27882, CVE-2024-27883)

  - A downgrade issue was addressed with additional code-signing restrictions. This issue is fixed in macOS
    Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, macOS Sonoma
    14.6. An app may be able to bypass Privacy preferences. (CVE-2024-40774)

  - A downgrade issue was addressed with additional code-signing restrictions. This issue is fixed in macOS
    Sonoma 14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. An app may be able to leak sensitive user
    information. (CVE-2024-40775)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS Monterey
    12.7.6, macOS Ventura 13.6.8. A local attacker may be able to elevate their privileges. (CVE-2024-40781,
    CVE-2024-40802)

  - The issue was addressed with improved restriction of data container access. This issue is fixed in macOS
    Sonoma 14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. A malicious application may be able to bypass
    Privacy preferences. (CVE-2024-40783)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 16.7.9 and
    iPadOS 16.7.9, macOS Ventura 13.6.8, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, visionOS 1.3,
    macOS Sonoma 14.6. Processing a maliciously crafted file may lead to unexpected app termination.
    (CVE-2024-40784)

  - This issue was addressed through improved state management. This issue is fixed in iOS 17.6 and iPadOS
    17.6, iOS 16.7.9 and iPadOS 16.7.9, macOS Ventura 13.6.8. An attacker may be able to view sensitive user
    information. (CVE-2024-40786)

  - This issue was addressed by adding an additional prompt for user consent. This issue is fixed in macOS
    Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, macOS Sonoma 14.6. A
    shortcut may be able to bypass Internet permission requirements. (CVE-2024-40787)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 16.7.9 and
    iPadOS 16.7.9, macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS
    17.6, visionOS 1.3, macOS Sonoma 14.6. A local attacker may be able to cause unexpected system shutdown.
    (CVE-2024-40788)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in iOS 16.7.9 and iPadOS
    16.7.9, macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, macOS Sonoma
    14.6. An app may be able to access user-sensitive data. (CVE-2024-40793)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.6, iOS 16.7.9 and iPadOS 16.7.9, macOS Monterey 12.7.6, macOS Ventura 13.6.8. Private
    browsing may leak some browsing history. (CVE-2024-40796)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.6, iOS 16.7.9 and iPadOS 16.7.9, macOS Monterey 12.7.6, macOS Ventura 13.6.8. An app may be able
    to read Safari's browsing history. (CVE-2024-40798)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in iOS
    16.7.9 and iPadOS 16.7.9, macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS
    10.6, tvOS 17.6, visionOS 1.3, macOS Sonoma 14.6. Processing a maliciously crafted file may lead to
    unexpected app termination. (CVE-2024-40799, CVE-2024-40806)

  - An input validation issue was addressed with improved input validation. This issue is fixed in macOS
    Sonoma 14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. An app may be able to modify protected parts of
    the file system. (CVE-2024-40800)

  - A type confusion issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS
    Monterey 12.7.6, macOS Ventura 13.6.8. An attacker may be able to cause unexpected app termination.
    (CVE-2024-40803)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS Monterey
    12.7.6, macOS Ventura 13.6.8. A shortcut may be able to use sensitive data with certain actions without
    prompting the user. (CVE-2024-40807)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.7.9 and iPadOS 16.7.9,
    macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, visionOS 1.3, macOS
    Sonoma 14.6. A shortcut may be able to bypass Internet permission requirements. (CVE-2024-40809,
    CVE-2024-40812)

  - A race condition was addressed with additional validation. This issue is fixed in macOS Ventura 13.6.8,
    iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, macOS Sonoma 14.6. A malicious attacker with arbitrary
    read and write capability may be able to bypass Pointer Authentication. (CVE-2024-40815)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in macOS Sonoma
    14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. A local attacker may be able to cause unexpected system
    shutdown. (CVE-2024-40816)

  - The issue was addressed with improved UI handling. This issue is fixed in macOS Sonoma 14.6, Safari 17.6,
    macOS Monterey 12.7.6, macOS Ventura 13.6.8. Visiting a website that frames malicious content may lead to
    UI spoofing. (CVE-2024-40817)

  - This issue was addressed by restricting options offered on a locked device. This issue is fixed in iOS
    16.7.9 and iPadOS 16.7.9, macOS Ventura 13.6.8, iOS 17.6 and iPadOS 17.6, watchOS 10.6, macOS Sonoma 14.6.
    An attacker with physical access may be able to use Siri to access sensitive user data. (CVE-2024-40818)

  - An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Sonoma
    14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. Third party app extensions may not receive the correct
    sandbox restrictions. (CVE-2024-40821)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS Monterey
    12.7.6, macOS Ventura 13.6.8. An app may be able to access user-sensitive data. (CVE-2024-40823)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS Monterey
    12.7.6, macOS Ventura 13.6.8. An app may be able to overwrite arbitrary files. (CVE-2024-40827)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, macOS Monterey
    12.7.6, macOS Ventura 13.6.8. A malicious app may be able to gain root privileges. (CVE-2024-40828)

  - The issue was addressed with improved checks. This issue is fixed in watchOS 10.6, iOS 17.6 and iPadOS
    17.6, iOS 16.7.9 and iPadOS 16.7.9, macOS Ventura 13.6.8. An attacker may be able to view restricted
    content from the lock screen. (CVE-2024-40829)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.6, iOS 16.7.9 and
    iPadOS 16.7.9, macOS Monterey 12.7.6, macOS Ventura 13.6.8. A shortcut may be able to use sensitive data
    with certain actions without prompting the user. (CVE-2024-40833)

  - This issue was addressed by adding an additional prompt for user consent. This issue is fixed in macOS
    Sonoma 14.6, macOS Monterey 12.7.6, macOS Ventura 13.6.8. A shortcut may be able to bypass sensitive
    Shortcuts app settings. (CVE-2024-40834)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.7.9 and iPadOS 16.7.9,
    macOS Ventura 13.6.8, macOS Monterey 12.7.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, macOS Sonoma 14.6. A
    shortcut may be able to use sensitive data with certain actions without prompting the user.
    (CVE-2024-40835)

  - A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition
    which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be
    able to trigger it by failing to authenticate within a set time period. (CVE-2024-6387)

  - A race condition in sshd affecting versions between 8.5p1 and 9.7p1 (inclusive) may allow arbitrary code
    execution with root privileges. Successful exploitation has been demonstrated on 32-bit Linux/glibc
    systems with ASLR. According to OpenSSH, the attack has been tested under lab conditions and requires on
    average 6-8 hours of continuous connections up to the maximum the server will accept. Exploitation on
    64-bit systems is believed to be possible but has not been demonstrated at this time.  (CVE-2024-6387)

  - An issue in the handling of URL protocols was addressed with improved logic. (CVE-2024-44205)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40786");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-6387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

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
  { 'fixed_version' : '13.6.8', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.6.8' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
