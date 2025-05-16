#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235718);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2024-8176",
    "CVE-2025-24142",
    "CVE-2025-24213",
    "CVE-2025-24222",
    "CVE-2025-24223",
    "CVE-2025-24274",
    "CVE-2025-26465",
    "CVE-2025-26466",
    "CVE-2025-30440",
    "CVE-2025-30443",
    "CVE-2025-31204",
    "CVE-2025-31205",
    "CVE-2025-31206",
    "CVE-2025-31208",
    "CVE-2025-31209",
    "CVE-2025-31212",
    "CVE-2025-31213",
    "CVE-2025-31215",
    "CVE-2025-31217",
    "CVE-2025-31218",
    "CVE-2025-31219",
    "CVE-2025-31220",
    "CVE-2025-31221",
    "CVE-2025-31222",
    "CVE-2025-31223",
    "CVE-2025-31224",
    "CVE-2025-31226",
    "CVE-2025-31232",
    "CVE-2025-31233",
    "CVE-2025-31234",
    "CVE-2025-31235",
    "CVE-2025-31236",
    "CVE-2025-31237",
    "CVE-2025-31238",
    "CVE-2025-31239",
    "CVE-2025-31240",
    "CVE-2025-31241",
    "CVE-2025-31242",
    "CVE-2025-31244",
    "CVE-2025-31245",
    "CVE-2025-31246",
    "CVE-2025-31247",
    "CVE-2025-31249",
    "CVE-2025-31250",
    "CVE-2025-31251",
    "CVE-2025-31256",
    "CVE-2025-31257",
    "CVE-2025-31258",
    "CVE-2025-31259",
    "CVE-2025-31260"
  );
  script_xref(name:"APPLE-SA", value:"122716");

  script_name(english:"macOS 15.x < 15.5 Multiple Vulnerabilities (122716)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.5. It is, therefore, affected by
multiple vulnerabilities:

  - A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A machine-in-the-middle
    attack can be performed by a malicious machine impersonating a legit server. This issue occurs due to how
    OpenSSH mishandles error codes in specific conditions when verifying the host key. For an attack to be
    considered successful, the attacker needs to manage to exhaust the client's memory resource first, turning
    the attack complexity high. (CVE-2025-26465)

  - A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity
    expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat
    can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could
    lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the
    environment and library usage. (CVE-2024-8176)

  - This issue was addressed with improved handling of floats. This issue is fixed in tvOS 18.4, Safari 18.4,
    iPadOS 17.7.6, iOS 18.4 and iPadOS 18.4, macOS Sequoia 15.4. A type confusion issue could lead to memory
    corruption. (CVE-2025-24213)

  - A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is
    allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client
    key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled
    increase in memory consumption on the server side. Consequently, the server may become unavailable,
    resulting in a denial of service attack. (CVE-2025-26466)

  - A privacy issue was addressed by removing the vulnerable code. This issue is fixed in macOS Ventura
    13.7.5, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An app may be able to access user-sensitive data.
    (CVE-2025-30443)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/122716");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '15.5.0', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
