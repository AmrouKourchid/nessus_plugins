#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170445);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id(
    "CVE-2022-0108",
    "CVE-2022-32221",
    "CVE-2022-35260",
    "CVE-2022-3705",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2023-23493",
    "CVE-2023-23496",
    "CVE-2023-23497",
    "CVE-2023-23498",
    "CVE-2023-23499",
    "CVE-2023-23500",
    "CVE-2023-23501",
    "CVE-2023-23502",
    "CVE-2023-23503",
    "CVE-2023-23504",
    "CVE-2023-23505",
    "CVE-2023-23506",
    "CVE-2023-23507",
    "CVE-2023-23508",
    "CVE-2023-23510",
    "CVE-2023-23511",
    "CVE-2023-23512",
    "CVE-2023-23513",
    "CVE-2023-23516",
    "CVE-2023-23517",
    "CVE-2023-23518",
    "CVE-2023-23519",
    "CVE-2023-23520",
    "CVE-2023-23530",
    "CVE-2023-23531",
    "CVE-2023-23539",
    "CVE-2023-28208",
    "CVE-2023-32393",
    "CVE-2023-32438",
    "CVE-2023-41990"
  );
  script_xref(name:"APPLE-SA", value:"HT213605");
  script_xref(name:"IAVA", value:"2023-A-0054-S");
  script_xref(name:"IAVA", value:"2023-A-0162-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/29");

  script_name(english:"macOS 13.x < 13.2 Multiple Vulnerabilities (HT213605)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.2. It is, therefore, affected by
multiple vulnerabilities:

  - This issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in tvOS
    16.3, macOS Ventura 13.2, watchOS 9.3, iOS 16.3 and iPadOS 16.3. An app may be able to bypass Privacy
    preferences. (CVE-2023-32438)

  - This issue was addressed by enabling hardened runtime. This issue is fixed in macOS Monterey 12.6.3, macOS
    Ventura 13.2, watchOS 9.3, macOS Big Sur 11.7.3, tvOS 16.3, iOS 16.3 and iPadOS 16.3. An app may be able
    to access user-sensitive data. (CVE-2023-23499)

  - A race condition was addressed with additional validation. This issue is fixed in watchOS 9.3, tvOS 16.3,
    macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. A user may be able to read arbitrary files as root.
    (CVE-2023-23520)

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur
    11.7.3, macOS Ventura 13.2, macOS Monterey 12.6.3. Mounting a maliciously crafted Samba network share may
    lead to arbitrary code execution. (CVE-2023-23513)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Ventura
    13.2. Mounting a maliciously crafted Samba network share may lead to arbitrary code execution.
    (CVE-2023-23539)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.2,
    macOS Monterey 12.6.3. An encrypted volume may be unmounted and remounted by a different user without
    prompting for the password. (CVE-2023-23493)

  - The issue was addressed with improved handling of caches. This issue is fixed in tvOS 16.3, iOS 16.3 and
    iPadOS 16.3, macOS Monterey 12.6.8, macOS Big Sur 11.7.9, iOS 15.7.8 and iPadOS 15.7.8, macOS Ventura
    13.2, watchOS 9.3. Processing a font file may lead to arbitrary code execution. Apple is aware of a report
    that this issue may have been actively exploited against versions of iOS released before iOS 15.7.1.
    (CVE-2023-41990)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.2, iOS 16.3
    and iPadOS 16.3. An app may be able to execute arbitrary code out of its sandbox or with certain elevated
    privileges. (CVE-2023-23530, CVE-2023-23531)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS
    9.3, tvOS 16.3, macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. Processing an image may lead to a denial-of-
    service. (CVE-2023-23519)

  - The issue was addressed with improved bounds checks. This issue is fixed in macOS Monterey 12.6.3, macOS
    Ventura 13.2. An app may be able to execute arbitrary code with kernel privileges. (CVE-2023-23507)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.7.3, macOS
    Ventura 13.2, macOS Monterey 12.6.3. An app may be able to execute arbitrary code with kernel privileges.
    (CVE-2023-23516)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Ventura 13.2, iOS 16.3
    and iPadOS 16.3, iOS 15.7.3 and iPadOS 15.7.3, tvOS 16.3, watchOS 9.3. An app may be able to leak
    sensitive kernel state. (CVE-2023-23500)

  - An information disclosure issue was addressed by removing the vulnerable code. This issue is fixed in
    macOS Monterey 12.6.3, macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3, tvOS 16.3, watchOS 9.3. An app may be
    able to determine kernel memory layout. (CVE-2023-23502)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.3, macOS
    Ventura 13.2, watchOS 9.3, iOS 15.7.3 and iPadOS 15.7.3, tvOS 16.3, iOS 16.3 and iPadOS 16.3. An app may
    be able to execute arbitrary code with kernel privileges. (CVE-2023-23504)

  - A permissions issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.2. An
    app may be able to access user-sensitive data. (CVE-2023-23506)

  - A logic issue was addressed with improved state management. This issue is fixed in iOS 15.7.3 and iPadOS
    15.7.3, macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. The quoted original message may be selected from the
    wrong email when forwarding an email from an Exchange account. (CVE-2023-23498)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.2, iOS
    16.3 and iPadOS 16.3, iOS 15.7.3 and iPadOS 15.7.3, tvOS 16.3, watchOS 9.3. An app may be able to bypass
    Privacy preferences. (CVE-2023-23503)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13.2, iOS
    16.3 and iPadOS 16.3. A user may send a text from a secondary eSIM despite configuring a contact to use a
    primary eSIM. (CVE-2023-28208)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.7.3,
    macOS Ventura 13.2, macOS Monterey 12.6.3. An app may be able to gain root privileges. (CVE-2023-23497)

  - A permissions issue was addressed with improved validation. This issue is fixed in macOS Ventura 13.2. An
    app may be able to access a user's Safari history. (CVE-2023-23510)

  - The issue was addressed with improved handling of caches. This issue is fixed in watchOS 9.3, tvOS 16.3,
    macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. Visiting a website may lead to an app denial-of-service.
    (CVE-2023-23512)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Monterey 12.6.3, macOS Ventura 13.2, watchOS 9.3, macOS Big Sur 11.7.3, iOS 15.7.3 and iPadOS
    15.7.3, iOS 16.3 and iPadOS 16.3. An app may be able to access information about a user's contacts.
    (CVE-2023-23505)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.3, macOS
    Ventura 13.2, iOS 16.3 and iPadOS 16.3, tvOS 16.3, watchOS 9.3. An app may be able to bypass Privacy
    preferences. (CVE-2023-23511)

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 9.3, tvOS 16.3,
    macOS Ventura 13.2, iOS 16.3 and iPadOS 16.3. Processing web content may lead to arbitrary code execution.
    (CVE-2023-32393)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.2, watchOS 9.3, iOS
    15.7.2 and iPadOS 15.7.2, Safari 16.3, tvOS 16.3, iOS 16.3 and iPadOS 16.3. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2023-23496)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.6.3, macOS
    Ventura 13.2, watchOS 9.3, macOS Big Sur 11.7.3, Safari 16.3, tvOS 16.3, iOS 16.3 and iPadOS 16.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2023-23517,
    CVE-2023-23518)

  - The issue was addressed with improved memory handling This issue is fixed in macOS Ventura 13.2. An app
    may be able to disclose kernel memory. (CVE-2023-23501)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.7.3, macOS
    Ventura 13.2, macOS Monterey 12.6.3. An app may be able to bypass Privacy preferences. (CVE-2023-23508)

  - Inappropriate implementation in Navigation in Google Chrome prior to 97.0.4692.71 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-0108)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213605");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0108");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23513");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

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
  { 'fixed_version' : '13.2.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.2' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
