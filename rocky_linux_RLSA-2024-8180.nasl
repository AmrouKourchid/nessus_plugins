#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:8180.
##

include('compat.inc');

if (description)
{
  script_id(209682);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/25");

  script_cve_id(
    "CVE-2024-23271",
    "CVE-2024-27820",
    "CVE-2024-27838",
    "CVE-2024-27851",
    "CVE-2024-40776",
    "CVE-2024-40779",
    "CVE-2024-40780",
    "CVE-2024-40782",
    "CVE-2024-40789",
    "CVE-2024-40866",
    "CVE-2024-44187"
  );
  script_xref(name:"RLSA", value:"2024:8180");

  script_name(english:"RockyLinux 9 : webkit2gtk3 (RLSA-2024:8180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:8180 advisory.

    * webkitgtk: webkit2gtk: Use after free may lead to Remote Code Execution (CVE-2024-40776)

    * webkitgtk: webkit2gtk: Processing maliciously crafted web content may lead to an unexpected process
    crash (CVE-2024-40789)

    * webkitgtk: webkit2gtk: Out-of-bounds read was addressed with improved bounds checking (CVE-2024-40780)

    * webkitgtk: webkit2gtk: Out-of-bounds read was addressed with improved bounds checking (CVE-2024-40779)

    * webkitgtk: webkit2gtk: Use-after-free was addressed with improved memory management (CVE-2024-40782)

    * webkitgtk: Visiting a malicious website may lead to address bar spoofing (CVE-2024-40866)

    * webkitgtk: A malicious website may cause unexpected cross-origin behavior (CVE-2024-23271)

    * webkitgtk: Processing web content may lead to arbitrary code execution (CVE-2024-27820)

    * webkitgtk: A maliciously crafted webpage may be able to fingerprint the user (CVE-2024-27838)

    * webkitgtk: Processing maliciously crafted web content may lead to arbitrary code execution
    (CVE-2024-27851)

    * webkitgtk: A malicious website may exfiltrate data cross-origin (CVE-2024-44187)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:8180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314706");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:webkit2gtk3-jsc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'webkit2gtk3-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-2.46.1-2.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debuginfo-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debuginfo-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debuginfo-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debuginfo-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debugsource-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debugsource-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debugsource-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-debugsource-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-2.46.1-2.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-2.46.1-2.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-debuginfo-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-2.46.1-2.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'webkit2gtk3-jsc-devel-debuginfo-2.46.1-2.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3 / webkit2gtk3-debuginfo / webkit2gtk3-debugsource / etc');
}
