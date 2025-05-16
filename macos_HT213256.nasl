##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161395);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2021-30946",
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2021-44224",
    "CVE-2021-44790",
    "CVE-2021-45444",
    "CVE-2021-46059",
    "CVE-2022-0128",
    "CVE-2022-0530",
    "CVE-2022-0778",
    "CVE-2022-22589",
    "CVE-2022-22630",
    "CVE-2022-22663",
    "CVE-2022-22665",
    "CVE-2022-22674",
    "CVE-2022-22675",
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23308",
    "CVE-2022-26697",
    "CVE-2022-26698",
    "CVE-2022-26706",
    "CVE-2022-26712",
    "CVE-2022-26714",
    "CVE-2022-26715",
    "CVE-2022-26718",
    "CVE-2022-26720",
    "CVE-2022-26721",
    "CVE-2022-26722",
    "CVE-2022-26723",
    "CVE-2022-26726",
    "CVE-2022-26728",
    "CVE-2022-26731",
    "CVE-2022-26745",
    "CVE-2022-26746",
    "CVE-2022-26748",
    "CVE-2022-26751",
    "CVE-2022-26755",
    "CVE-2022-26756",
    "CVE-2022-26757",
    "CVE-2022-26761",
    "CVE-2022-26763",
    "CVE-2022-26766",
    "CVE-2022-26767",
    "CVE-2022-26768",
    "CVE-2022-26769",
    "CVE-2022-26770",
    "CVE-2022-26776",
    "CVE-2022-32790",
    "CVE-2022-32794",
    "CVE-2022-32882"
  );
  script_xref(name:"IAVA", value:"2022-A-0212-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");
  script_xref(name:"APPLE-SA", value:"HT213256");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");

  script_name(english:"macOS 11.x < 11.6.6 Multiple Vulnerabilities (HT213256)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.6. It is, therefore, affected by
multiple vulnerabilities:

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Monterey 12.1,
    watchOS 8.3, iOS 15.2 and iPadOS 15.2, macOS Big Sur 11.6.2. A malicious application may be able to bypass
    certain Privacy preferences. (CVE-2021-30946)

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-4136)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4166, CVE-2021-4193, CVE-2022-0128)

  - vim is vulnerable to Use After Free (CVE-2021-4173, CVE-2021-4187, CVE-2021-4192)

  - A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL
    pointer dereference) or, for configurations mixing forward and reverse proxy declarations, can allow for
    requests to be directed to a declared Unix Domain Socket endpoint (Server Side Request Forgery). This
    issue affects Apache HTTP Server 2.4.7 up to 2.4.51 (included). (CVE-2021-44224)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser
    (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the
    vulnerabilty though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and
    earlier. (CVE-2021-44790)

  - In zsh before 5.8.1, an attacker can achieve code execution if they control a command output inside the
    prompt, as demonstrated by a %F argument. This occurs because of recursive PROMPT_SUBST expansion.
    (CVE-2021-45444)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn
    by its CNA. Further investigation showed that it was not a security issue. Notes: none (CVE-2021-46059)

  - A flaw was found in Unzip. The vulnerability occurs during the conversion of a wide string to a local
    string that leads to a heap of out-of-bound write. This flaw allows an attacker to input a specially
    crafted zip file, leading to a crash or code execution. (CVE-2022-0530)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in iOS 15.3 and
    iPadOS 15.3, watchOS 8.4, tvOS 15.3, Safari 15.3, macOS Monterey 12.2. Processing a maliciously crafted
    mail message may lead to running arbitrary javascript. (CVE-2022-22589)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.6.6, macOS Monterey 12.3, Security Update 2022-004 Catalina. A remote user may cause an unexpected app
    termination or arbitrary code execution (CVE-2022-22630)

  - This issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in iOS
    15.4 and iPadOS 15.4, Security Update 2022-004 Catalina, macOS Monterey 12.3, macOS Big Sur 11.6.6. A
    malicious application may bypass Gatekeeper checks. (CVE-2022-22663)

  - A logic issue was addressed with improved validation. This issue is fixed in macOS Monterey 12.3. A
    malicious application may be able to gain root privileges. (CVE-2022-22665)

  - An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with
    improved input validation. This issue is fixed in macOS Monterey 12.3.1, Security Update 2022-004
    Catalina, macOS Big Sur 11.6.6. A local user may be able to read kernel memory. (CVE-2022-22674)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in tvOS
    15.5, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.3.1, iOS 15.4.1 and iPadOS 15.4.1. An
    application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that
    this issue may have been actively exploited.. (CVE-2022-22675)

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - valid.c in libxml2 before 2.9.13 has a use-after-free of ID and IDREF attributes. (CVE-2022-23308)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. Processing a maliciously crafted
    AppleScript binary may result in unexpected application termination or disclosure of process memory.
    (CVE-2022-26697)

  - An out-of-bounds read issue was addressed with improved bounds checking. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. Processing a maliciously crafted
    AppleScript binary may result in unexpected application termination or disclosure of process memory.
    (CVE-2022-26698)

  - An access issue was addressed with additional sandbox restrictions on third-party applications. This issue
    is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. A
    sandboxed process may be able to circumvent sandbox restrictions. (CVE-2022-26706)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Monterey 12.4,
    macOS Big Sur 11.6.6. A malicious application may be able to modify protected parts of the file system.
    (CVE-2022-26712)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in tvOS 15.5, iOS
    15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey
    12.4. An application may be able to execute arbitrary code with kernel privileges. (CVE-2022-26714)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. An application may be able to gain
    elevated privileges. (CVE-2022-26715)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in macOS
    Monterey 12.4, macOS Big Sur 11.6.6. An application may be able to gain elevated privileges.
    (CVE-2022-26718)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able
    to execute arbitrary code with kernel privileges. (CVE-2022-26720)

  - A memory initialization issue was addressed. This issue is fixed in Security Update 2022-004 Catalina,
    macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able to gain root privileges.
    (CVE-2022-26721, CVE-2022-26722)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS
    Monterey 12.4, macOS Big Sur 11.6.6. Mounting a maliciously crafted Samba network share may lead to
    arbitrary code execution. (CVE-2022-26723)

  - This issue was addressed with improved checks. This issue is fixed in Security Update 2022-004 Catalina,
    watchOS 8.6, macOS Monterey 12.4, macOS Big Sur 11.6.6. An app may be able to capture a user's screen.
    (CVE-2022-26726)

  - This issue was addressed with improved entitlements. This issue is fixed in Security Update 2022-004
    Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able to access
    restricted files. (CVE-2022-26728)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.4,
    iOS 15.5 and iPadOS 15.5. A malicious website may be able to track users in Safari private browsing mode.
    (CVE-2022-26731)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in macOS Big Sur
    11.6.6. A malicious application may disclose restricted memory. (CVE-2022-26745)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in Security Update 2022-004
    Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able to bypass Privacy
    preferences. (CVE-2022-26746)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. Processing maliciously crafted web
    content may lead to arbitrary code execution. (CVE-2022-26748)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in iTunes
    12.12.4 for Windows, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, macOS Big Sur 11.6.6,
    macOS Monterey 12.4. Processing a maliciously crafted image may lead to arbitrary code execution.
    (CVE-2022-26751)

  - This issue was addressed with improved environment sanitization. This issue is fixed in Security Update
    2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able to break
    out of its sandbox. (CVE-2022-26755)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. An application may be able to execute
    arbitrary code with kernel privileges. (CVE-2022-26756)

  - A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.5,
    iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS
    Monterey 12.4. An application may be able to execute arbitrary code with kernel privileges.
    (CVE-2022-26757)

  - A memory corruption issue was addressed with improved memory handling. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Big Sur 11.6.6. An application may be able to execute arbitrary code with
    kernel privileges. (CVE-2022-26761)

  - An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in tvOS
    15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6,
    macOS Monterey 12.4. A malicious application may be able to execute arbitrary code with system privileges.
    (CVE-2022-26763)

  - A certificate parsing issue was addressed with improved checks. This issue is fixed in tvOS 15.5, iOS 15.5
    and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey
    12.4. A malicious app may be able to bypass signature validation. (CVE-2022-26766)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Monterey 12.4,
    macOS Big Sur 11.6.6. A malicious application may be able to bypass Privacy preferences. (CVE-2022-26767)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS
    Monterey 12.4, watchOS 8.6, tvOS 15.5, macOS Big Sur 11.6.6. An application may be able to execute
    arbitrary code with kernel privileges. (CVE-2022-26768)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able
    to execute arbitrary code with kernel privileges. (CVE-2022-26769)

  - An out-of-bounds read issue was addressed with improved input validation. This issue is fixed in Security
    Update 2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able
    to execute arbitrary code with kernel privileges. (CVE-2022-26770)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.4, macOS Big Sur
    11.6.6. An attacker may be able to cause unexpected application termination or arbitrary code execution.
    (CVE-2022-26776)

  - This issue was addressed with improved checks. This issue is fixed in tvOS 15.5, watchOS 8.6, iOS 15.5 and
    iPadOS 15.5, macOS Monterey 12.4, macOS Big Sur 11.6.6, Security Update 2022-004 Catalina. A remote user
    may be able to cause a denial-of-service. (CVE-2022-32790)

  - A logic issue was addressed with improved state management. This issue is fixed in Security Update
    2022-004 Catalina, macOS Monterey 12.4, macOS Big Sur 11.6.6. An app may be able to gain elevated
    privileges. (CVE-2022-32794)

  - This issue was addressed with improved checks. This issue is fixed in macOS Monterey 12.4, macOS Big Sur
    11.6.6. An app may be able to bypass Privacy preferences. (CVE-2022-32882)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213256");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26770");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32882");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '11.6.6', 'min_version' : '11.0', 'fixed_display' : 'macOS Big Sur 11.6.6' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
