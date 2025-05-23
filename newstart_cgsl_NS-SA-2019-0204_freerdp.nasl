#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0204. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129918);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2018-1000852");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : freerdp Vulnerability (NS-SA-2019-0204)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has freerdp packages installed that are affected
by a vulnerability:

  - FreeRDP FreeRDP 2.0.0-rc3 released version before commit
    205c612820dac644d665b5bb1cdf437dc5ca01e3 contains a
    Other/Unknown vulnerability in
    channels/drdynvc/client/drdynvc_main.c,
    drdynvc_process_capability_request that can result in
    The RDP server can read the client's memory.. This
    attack appear to be exploitable via RDPClient must
    connect the rdp server with echo option. This
    vulnerability appears to have been fixed in after commit
    205c612820dac644d665b5bb1cdf437dc5ca01e3.
    (CVE-2018-1000852)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0204");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freerdp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000852");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "freerdp-2.0.0-1.rc4.el7",
    "freerdp-debuginfo-2.0.0-1.rc4.el7",
    "freerdp-devel-2.0.0-1.rc4.el7",
    "freerdp-libs-2.0.0-1.rc4.el7",
    "libwinpr-2.0.0-1.rc4.el7",
    "libwinpr-devel-2.0.0-1.rc4.el7"
  ],
  "CGSL MAIN 5.04": [
    "freerdp-2.0.0-1.rc4.el7",
    "freerdp-debuginfo-2.0.0-1.rc4.el7",
    "freerdp-devel-2.0.0-1.rc4.el7",
    "freerdp-libs-2.0.0-1.rc4.el7",
    "libwinpr-2.0.0-1.rc4.el7",
    "libwinpr-devel-2.0.0-1.rc4.el7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
