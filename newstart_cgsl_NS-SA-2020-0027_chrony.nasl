#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0027. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136904);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2012-4502", "CVE-2012-4503", "CVE-2014-0021");
  script_bugtraq_id(61700, 61703, 65035);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : chrony Multiple Vulnerabilities (NS-SA-2020-0027)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has chrony packages installed that are affected by
multiple vulnerabilities:

  - Multiple integer overflows in pktlength.c in Chrony
    before 1.29 allow remote attackers to cause a denial of
    service (crash) via a crafted (1) REQ_SUBNETS_ACCESSED
    or (2) REQ_CLIENT_ACCESSES command request to the
    PKL_CommandLength function or crafted (3)
    RPY_SUBNETS_ACCESSED, (4) RPY_CLIENT_ACCESSES, (5)
    RPY_CLIENT_ACCESSES_BY_INDEX, or (6) RPY_MANUAL_LIST
    command reply to the PKL_ReplyLength function, which
    triggers an out-of-bounds read or buffer overflow. NOTE:
    versions 1.27 and 1.28 do not require authentication to
    exploit. (CVE-2012-4502)

  - cmdmon.c in Chrony before 1.29 allows remote attackers
    to obtain potentially sensitive information from stack
    memory via vectors related to (1) an invalid subnet in a
    RPY_SUBNETS_ACCESSED command to the
    handle_subnets_accessed function or (2) a
    RPY_CLIENT_ACCESSES command to the
    handle_client_accesses function when client logging is
    disabled, which causes uninitialized data to be included
    in a reply. (CVE-2012-4503)

  - Chrony before 1.29.1 has traffic amplification in cmdmon
    protocol (CVE-2014-0021)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0027");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL chrony packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0021");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "chrony-3.2-2.el7.cgslv5.0.1.g29cef58",
    "chrony-debuginfo-3.2-2.el7.cgslv5.0.1.g29cef58"
  ],
  "CGSL MAIN 5.04": [
    "chrony-3.2-2.el7.cgslv5.0.1.g29cef58",
    "chrony-debuginfo-3.2-2.el7.cgslv5.0.1.g29cef58"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chrony");
}
