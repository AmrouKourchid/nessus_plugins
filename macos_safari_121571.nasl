#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212192);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2024-44229",
    "CVE-2024-44244",
    "CVE-2024-44259",
    "CVE-2024-44296"
  );

  script_name(english:"Apple Safari 18.1 Multiple Vulnerabilities (121571)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is prior to 18.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the 121571 advisory.

  - An information leakage was addressed with additional validation. This issue is fixed in visionOS 2.1, iOS
    18.1 and iPadOS 18.1, macOS Sequoia 15.1, Safari 18.1. Private browsing may leak some browsing history.
    (CVE-2024-44229)

  - A memory corruption issue was addressed with improved input validation. This issue is fixed in iOS 18.1
    and iPadOS 18.1, watchOS 11.1, visionOS 2.1, tvOS 18.1, macOS Sequoia 15.1, Safari 18.1. Processing
    maliciously crafted web content may lead to an unexpected process crash. (CVE-2024-44244)

  - This issue was addressed through improved state management. This issue is fixed in iOS 17.7.1 and iPadOS
    17.7.1, visionOS 2.1, iOS 18.1 and iPadOS 18.1, macOS Sequoia 15.1, Safari 18.1. An attacker may be able
    to misuse a trust relationship to download malicious content. (CVE-2024-44259)

  - The issue was addressed with improved checks. This issue is fixed in tvOS 18.1, iOS 18.1 and iPadOS 18.1,
    iOS 17.7.1 and iPadOS 17.7.1, watchOS 11.1, visionOS 2.1, macOS Sequoia 15.1, Safari 18.1. Processing
    maliciously crafted web content may prevent Content Security Policy from being enforced. (CVE-2024-44296)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121571");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 18.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_apple_safari_installed.nbin");
  script_require_keys("installed_sw/Apple Safari", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Apple Safari');

var constraints = [
  { 'fixed_version' : '18.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
