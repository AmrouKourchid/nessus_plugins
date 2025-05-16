#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212177);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2024-40857",
    "CVE-2024-40866",
    "CVE-2024-44155",
    "CVE-2024-44187",
    "CVE-2024-44202"
  );

  script_name(english:"Apple Safari 18.0 Multiple Vulnerabilities (121241)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is prior to 18.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the 121241 advisory.

  - This issue was addressed through improved state management. This issue is fixed in Safari 18, visionOS 2,
    watchOS 11, macOS Sequoia 15, iOS 18 and iPadOS 18, tvOS 18. Processing maliciously crafted web content
    may lead to universal cross site scripting. (CVE-2024-40857)

  - The issue was addressed with improved UI. This issue is fixed in Safari 18, macOS Sequoia 15. Visiting a
    malicious website may lead to address bar spoofing. (CVE-2024-40866)

  - A custom URL scheme handling issue was addressed with improved input validation. This issue is fixed in
    Safari 18, iOS 17.7.1 and iPadOS 17.7.1, macOS Sequoia 15, watchOS 11, iOS 18 and iPadOS 18. Maliciously
    crafted web content may violate iframe sandboxing policy. (CVE-2024-44155)

  - A cross-origin issue existed with iframe elements. This was addressed with improved tracking of security
    origins. This issue is fixed in Safari 18, visionOS 2, watchOS 11, macOS Sequoia 15, iOS 18 and iPadOS 18,
    tvOS 18. A malicious website may exfiltrate data cross-origin. (CVE-2024-44187)

  - An authentication issue was addressed with improved state management. This issue is fixed in iOS 18 and
    iPadOS 18. Private Browsing tabs may be accessed without authentication. (CVE-2024-44202)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121241");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 18.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/16");
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
  { 'fixed_version' : '18.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
