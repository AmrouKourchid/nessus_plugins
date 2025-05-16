#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:9552.
##

include('compat.inc');

if (description)
{
  script_id(211578);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id(
    "CVE-2024-9680",
    "CVE-2024-10458",
    "CVE-2024-10459",
    "CVE-2024-10460",
    "CVE-2024-10461",
    "CVE-2024-10462",
    "CVE-2024-10463",
    "CVE-2024-10464",
    "CVE-2024-10465",
    "CVE-2024-10466",
    "CVE-2024-10467"
  );
  script_xref(name:"ALSA", value:"2024:9552");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/05");
  script_xref(name:"RHSA", value:"2024:9552");

  script_name(english:"AlmaLinux 9 : thunderbird (ALSA-2024:9552)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2024:9552 advisory.

    * firefox: Use-after-free in Animation timeline (128.3.1 ESR Chemspill) (CVE-2024-9680)
      * firefox: thunderbird: History interface could have been used to cause a Denial of Service condition in
    the browser (CVE-2024-10464)
      * firefox: thunderbird: XSS due to Content-Disposition being ignored in multipart/x-mixed-replace
    response (CVE-2024-10461)
      * firefox: thunderbird: Permission leak via embed or object elements (CVE-2024-10458)
      * firefox: thunderbird: Use-after-free in layout with accessibility (CVE-2024-10459)
      * firefox: thunderbird: Memory safety bugs fixed in Firefox 132, Thunderbird 132, Firefox ESR 128.4, and
    Thunderbird 128.4 (CVE-2024-10467)
      * firefox: thunderbird: Clipboard paste button persisted across tabs (CVE-2024-10465)
      * firefox: DOM push subscription message could hang Firefox (CVE-2024-10466)
      * firefox: thunderbird: Cross origin video frame leak (CVE-2024-10463)
      * firefox: thunderbird: Origin of permission prompt could be spoofed by long URL (CVE-2024-10462)
      * firefox: thunderbird: Confusing display of origin for external protocol handler prompt
    (CVE-2024-10460)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-9552.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:9552");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9680");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(120, 20, 280, 400, 416, 79, 799, 940, 942);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'thunderbird-128.4.0-1.el9_5.alma.1', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-128.4.0-1.el9_5.alma.1', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-128.4.0-1.el9_5.alma.1', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-128.4.0-1.el9_5.alma.1', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
