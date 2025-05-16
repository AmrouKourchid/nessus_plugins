#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215229);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id(
    "CVE-2023-28826",
    "CVE-2023-40389",
    "CVE-2024-23201",
    "CVE-2024-23204",
    "CVE-2024-23216",
    "CVE-2024-23218",
    "CVE-2024-23225",
    "CVE-2024-23227",
    "CVE-2024-23230",
    "CVE-2024-23234",
    "CVE-2024-23244",
    "CVE-2024-23245",
    "CVE-2024-23247",
    "CVE-2024-23257",
    "CVE-2024-23264",
    "CVE-2024-23265",
    "CVE-2024-23266",
    "CVE-2024-23267",
    "CVE-2024-23268",
    "CVE-2024-23269",
    "CVE-2024-23270",
    "CVE-2024-23272",
    "CVE-2024-23274",
    "CVE-2024-23275",
    "CVE-2024-23276",
    "CVE-2024-23283",
    "CVE-2024-23286",
    "CVE-2024-23299"
  );
  script_xref(name:"APPLE-SA", value:"120884");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/27");

  script_name(english:"macOS 12.x < 12.7.4 Multiple Vulnerabilities (120884)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.7.4. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Ventura
    13.6.5, macOS Monterey 12.7.4. An app may be able to break out of its sandbox. (CVE-2024-23299)

  - The issue was addressed with additional permissions checks. This issue is fixed in macOS Sonoma 14.3,
    watchOS 10.3, iOS 17.3 and iPadOS 17.3. A shortcut may be able to use sensitive data with certain actions
    without prompting the user. (CVE-2024-23204)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS
    16.7.6 and iPadOS 16.7.6, macOS Monterey 12.7.4, macOS Sonoma 14.1, macOS Ventura 13.6.5. An app may be
    able to access sensitive user data. (CVE-2023-28826)

  - The issue was addressed with improved restriction of data container access. This issue is fixed in macOS
    Ventura 13.6.5, macOS Monterey 12.7.4. An app may be able to access sensitive user data. (CVE-2023-40389)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Monterey
    12.7.4, watchOS 10.3, tvOS 17.3, macOS Ventura 13.6.5, iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3. An app
    may be able to cause a denial-of-service. (CVE-2024-23201)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23204");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23299");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:12.0");
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
  { 'fixed_version' : '12.7.4', 'min_version' : '12.0', 'fixed_display' : 'macOS Monterey 12.7.4' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
