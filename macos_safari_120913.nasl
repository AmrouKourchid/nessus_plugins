#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212176);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id(
    "CVE-2024-4558",
    "CVE-2024-40776",
    "CVE-2024-40779",
    "CVE-2024-40780",
    "CVE-2024-40782",
    "CVE-2024-40785",
    "CVE-2024-40789",
    "CVE-2024-40794",
    "CVE-2024-40817",
    "CVE-2024-44185",
    "CVE-2024-44206"
  );

  script_name(english:"Apple Safari 17.6 Multiple Vulnerabilities (120913)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is prior to 17.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the 120913 advisory.

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 16.7.9
    and iPadOS 16.7.9, Safari 17.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, visionOS 1.3, macOS
    Sonoma 14.6. Processing maliciously crafted web content may lead to an unexpected process crash.
    (CVE-2024-40776, CVE-2024-40782)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in iOS 16.7.9 and
    iPadOS 16.7.9, Safari 17.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, visionOS 1.3, macOS Sonoma
    14.6. Processing maliciously crafted web content may lead to an unexpected process crash. (CVE-2024-40779,
    CVE-2024-40780)

  - This issue was addressed with improved checks. This issue is fixed in iOS 16.7.9 and iPadOS 16.7.9, Safari
    17.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, visionOS 1.3, macOS Sonoma 14.6. Processing
    maliciously crafted web content may lead to a cross site scripting attack. (CVE-2024-40785)

  - An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in iOS
    16.7.9 and iPadOS 16.7.9, Safari 17.6, iOS 17.6 and iPadOS 17.6, watchOS 10.6, tvOS 17.6, visionOS 1.3,
    macOS Sonoma 14.6. Processing maliciously crafted web content may lead to an unexpected process crash.
    (CVE-2024-40789)

  - This issue was addressed through improved state management. This issue is fixed in macOS Sonoma 14.6, iOS
    17.6 and iPadOS 17.6, Safari 17.6. Private Browsing tabs may be accessed without authentication.
    (CVE-2024-40794)

  - The issue was addressed with improved UI handling. This issue is fixed in macOS Sonoma 14.6, Safari 17.6,
    macOS Monterey 12.7.6, macOS Ventura 13.6.8. Visiting a website that frames malicious content may lead to
    UI spoofing. (CVE-2024-40817)

  - The issue was addressed with improved checks. This issue is fixed in tvOS 17.6, visionOS 1.3, Safari 17.6,
    watchOS 10.6, iOS 17.6 and iPadOS 17.6, macOS Sonoma 14.6. Processing maliciously crafted web content may
    lead to an unexpected process crash. (CVE-2024-44185)

  - An issue in the handling of URL protocols was addressed with improved logic. This issue is fixed in tvOS
    17.6, visionOS 1.3, Safari 17.6, watchOS 10.6, iOS 17.6 and iPadOS 17.6, macOS Sonoma 14.6. A user may be
    able to bypass some web content restrictions. (CVE-2024-44206)

  - Use after free in ANGLE in Google Chrome prior to 124.0.6367.155 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4558)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120913");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 17.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4558");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/29");
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
  { 'fixed_version' : '17.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
