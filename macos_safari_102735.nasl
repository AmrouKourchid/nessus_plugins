#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212173);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2023-28204",
    "CVE-2023-32373",
    "CVE-2023-32402",
    "CVE-2023-32409",
    "CVE-2023-32423"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");

  script_name(english:"Apple Safari 16.5 Multiple Vulnerabilities (102735)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is prior to 16.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the 102735 advisory.

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, Safari 16.5, iOS 16.5 and iPadOS 16.5.
    Processing web content may disclose sensitive information. Apple is aware of a report that this issue may
    have been actively exploited. (CVE-2023-28204)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, iOS 15.7.6 and iPadOS 15.7.6, Safari 16.5, iOS 16.5 and iPadOS 16.5.
    Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a
    report that this issue may have been actively exploited. (CVE-2023-32373)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, Safari 16.5, iOS 16.5 and iPadOS 16.5. Processing web content may disclose
    sensitive information. (CVE-2023-32402)

  - The issue was addressed with improved bounds checks. This issue is fixed in watchOS 9.5, tvOS 16.5, macOS
    Ventura 13.4, iOS 15.7.8 and iPadOS 15.7.8, Safari 16.5, iOS 16.5 and iPadOS 16.5. A remote attacker may
    be able to break out of Web Content sandbox. Apple is aware of a report that this issue may have been
    actively exploited. (CVE-2023-32409)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in watchOS 9.5,
    tvOS 16.5, macOS Ventura 13.4, Safari 16.5, iOS 16.5 and iPadOS 16.5. Processing web content may disclose
    sensitive information. (CVE-2023-32423)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/102735");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 16.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32373");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
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
  { 'fixed_version' : '16.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
