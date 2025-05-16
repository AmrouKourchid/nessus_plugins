#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:2616.
##

include('compat.inc');

if (description)
{
  script_id(196961);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31083");
  script_xref(name:"RLSA", value:"2024:2616");

  script_name(english:"Rocky Linux 9 : tigervnc (RLSA-2024:2616)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:2616 advisory.

  - A heap-based buffer over-read vulnerability was found in the X.org server's ProcXIGetSelectedEvents()
    function. This issue occurs when byte-swapped length values are used in replies, potentially leading to
    memory leakage and segmentation faults, particularly when triggered by a client with a different
    endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory
    values and then transmit them back to the client until encountering an unmapped page, resulting in a
    crash. Despite the attacker's inability to control the specific memory copied into the replies, the small
    length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds
    reads. (CVE-2024-31080)

  - A heap-based buffer over-read vulnerability was found in the X.org server's ProcXIPassiveGrabDevice()
    function. This issue occurs when byte-swapped length values are used in replies, potentially leading to
    memory leakage and segmentation faults, particularly when triggered by a client with a different
    endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory
    values and then transmit them back to the client until encountering an unmapped page, resulting in a
    crash. Despite the attacker's inability to control the specific memory copied into the replies, the small
    length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds
    reads. (CVE-2024-31081)

  - A use-after-free vulnerability was found in the ProcRenderAddGlyphs() function of Xorg servers. This issue
    occurs when AllocateGlyph() is called to store new glyphs sent by the client to the X server, potentially
    resulting in multiple entries pointing to the same non-refcounted glyphs. Consequently,
    ProcRenderAddGlyphs() may free a glyph, leading to a use-after-free scenario when the same glyph pointer
    is subsequently accessed. This flaw allows an authenticated attacker to execute arbitrary code on the
    system by sending a specially crafted request. (CVE-2024-31083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:2616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272000");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-31083");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:tigervnc-server-module-debuginfo");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'tigervnc-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debuginfo-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debuginfo-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debuginfo-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debugsource-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debugsource-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-debugsource-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.13.1-8.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.13.1-8.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-selinux-1.13.1-8.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-debuginfo-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-debuginfo-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-debuginfo-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-debuginfo-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-debuginfo-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-debuginfo-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-debuginfo-1.13.1-8.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-debuginfo-1.13.1-8.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-debuginfo-1.13.1-8.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tigervnc / tigervnc-debuginfo / tigervnc-debugsource / etc');
}
