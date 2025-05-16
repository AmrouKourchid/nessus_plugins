#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207286);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id(
    "CVE-2024-27876",
    "CVE-2024-27886",
    "CVE-2024-40791",
    "CVE-2024-40797",
    "CVE-2024-40814",
    "CVE-2024-40844",
    "CVE-2024-40847",
    "CVE-2024-40848",
    "CVE-2024-40850",
    "CVE-2024-44128",
    "CVE-2024-44129",
    "CVE-2024-44151",
    "CVE-2024-44158",
    "CVE-2024-44160",
    "CVE-2024-44161",
    "CVE-2024-44163",
    "CVE-2024-44164",
    "CVE-2024-44165",
    "CVE-2024-44166",
    "CVE-2024-44167",
    "CVE-2024-44168",
    "CVE-2024-44169",
    "CVE-2024-44176",
    "CVE-2024-44177",
    "CVE-2024-44178",
    "CVE-2024-44181",
    "CVE-2024-44182",
    "CVE-2024-44183",
    "CVE-2024-44184",
    "CVE-2024-44190",
    "CVE-2024-54469"
  );
  script_xref(name:"APPLE-SA", value:"121234");
  script_xref(name:"IAVA", value:"2024-A-0578-S");
  script_xref(name:"IAVA", value:"2024-A-0692-S");
  script_xref(name:"IAVA", value:"2024-A-0761-S");

  script_name(english:"macOS 13.x < 13.7 Multiple Vulnerabilities (121234)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.7. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.7, iOS 17.7 and
    iPadOS 17.7, visionOS 2, iOS 18 and iPadOS 18, macOS Sonoma 14.7, macOS Sequoia 15. Network traffic may
    leak outside a VPN tunnel. (CVE-2024-44165)

  - A race condition was addressed with improved locking. This issue is fixed in macOS Ventura 13.7, iOS 17.7
    and iPadOS 17.7, visionOS 2, iOS 18 and iPadOS 18, macOS Sonoma 14.7, macOS Sequoia 15. Unpacking a
    maliciously crafted archive may allow an attacker to write arbitrary files. (CVE-2024-27876)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.4. An
    unprivileged app may be able to log keystrokes in other apps including those using secure input mode.
    (CVE-2024-27886)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.7, iOS 17.7 and iPadOS 17.7, iOS 18 and iPadOS 18, macOS Sonoma 14.7, macOS Sequoia 15.
    An app may be able to access information about a user's contacts. (CVE-2024-40791)

  - This issue was addressed through improved state management. This issue is fixed in macOS Ventura 13.7,
    macOS Sonoma 14.7, macOS Sequoia 15. Visiting a malicious website may lead to user interface spoofing.
    (CVE-2024-40797)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121234");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.7.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.7' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
