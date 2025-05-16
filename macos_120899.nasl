#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214268);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-23229",
    "CVE-2024-27789",
    "CVE-2024-27796",
    "CVE-2024-27798",
    "CVE-2024-27799",
    "CVE-2024-27800",
    "CVE-2024-27802",
    "CVE-2024-27805",
    "CVE-2024-27806",
    "CVE-2024-27810",
    "CVE-2024-27817",
    "CVE-2024-27823",
    "CVE-2024-27824",
    "CVE-2024-27831",
    "CVE-2024-27840",
    "CVE-2024-27843",
    "CVE-2024-27847",
    "CVE-2024-27885",
    "CVE-2024-40771"
  );
  script_xref(name:"APPLE-SA", value:"120899");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 12.x < 12.7.5 Multiple Vulnerabilities (120899)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.5. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.5. An app may be
    able to elevate privileges. (CVE-2024-27843)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Monterey 12.7.5, macOS Ventura 13.6.5, macOS Sonoma 14.4. A malicious application may be able to access
    Find My data. (CVE-2024-23229)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.7.8 and iPadOS 16.7.8,
    macOS Monterey 12.7.5, macOS Ventura 13.6.7, macOS Sonoma 14.4. An app may be able to access user-
    sensitive data. (CVE-2024-27789)

  - The issue was addressed with improved checks. This issue is fixed in iOS 17.5 and iPadOS 17.5, macOS
    Sonoma 14.5. An attacker may be able to elevate privileges. (CVE-2024-27796)

  - An authorization issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.5. An attacker may be able to elevate privileges. (CVE-2024-27798)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120899");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27843");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-40771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'fixed_version' : '12.7.5', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
