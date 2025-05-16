#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214562);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2025-21502");

  script_name(english:"OpenJDK 8 <= 8u432 / 11.0.0 <= 11.0.25 / 17.0.0 <= 17.0.13 / 21.0.0 <= 21.0.5 / 23.0.0 <= 23.0.1 Vulnerability (2025-01-21)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is 8 prior to 8u432 / 11.0.0 prior to 11.0.25 / 17.0.0 prior to
17.0.13 / 21.0.0 prior to 21.0.5 / 23.0.0 prior to 23.0.1. It is, therefore, affected by a vulnerability as referenced
in the 2025-01-21 advisory.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u431-perf,
    11.0.25, 17.0.13, 21.0.5, 23.0.1; Oracle GraalVM for JDK: 17.0.13, 21.0.5, 23.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.16 and 21.3.12. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Java SE,
    Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. (CVE-2025-21502)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2025-01-21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 8u432 / 11.0.25 / 17.0.13 / 21.0.5 / 23.0.1");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adoptopenjdk_nix_installed.nbin", "adoptopenjdk_win_installed.nbin", "openjdk_win_installed.nbin", "openjdk_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = [
        'OpenJDK Java',
        'AdoptOpenJDK'
];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '8.0.0', 'max_version' : '8.0.432', 'fixed_display' : 'Upgrade to a version greater than 8u432' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.25', 'fixed_display' : 'Upgrade to a version greater than 11.0.25' },
  { 'min_version' : '17.0.0', 'max_version' : '17.0.13', 'fixed_display' : 'Upgrade to a version greater than 17.0.13' },
  { 'min_version' : '21.0.0', 'max_version' : '21.0.5', 'fixed_display' : 'Upgrade to a version greater than 21.0.5' },
  { 'min_version' : '23.0.0', 'max_version' : '23.0.1', 'fixed_display' : 'Upgrade to a version greater than 23.0.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
