#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:4251.
##

include('compat.inc');

if (description)
{
  script_id(185024);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id(
    "CVE-2018-5727",
    "CVE-2018-5785",
    "CVE-2018-20845",
    "CVE-2018-20847",
    "CVE-2019-12973",
    "CVE-2020-15389",
    "CVE-2020-27814",
    "CVE-2020-27823",
    "CVE-2020-27824",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27845",
    "CVE-2021-3575",
    "CVE-2021-29338"
  );
  script_xref(name:"RLSA", value:"2021:4251");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Rocky Linux 8 : openjpeg2 (RLSA-2021:4251)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:4251 advisory.

  - Division-by-zero vulnerabilities in the functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in
    openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a denial of service (application
    crash). (CVE-2018-20845)

  - An improper computation of p_tx0, p_tx1, p_ty0 and p_ty1 in the function opj_get_encoding_parameters in
    openjp2/pi.c in OpenJPEG through 2.3.0 can lead to an integer overflow. (CVE-2018-20847)

  - In OpenJPEG 2.3.0, there is an integer overflow vulnerability in the opj_t1_encode_cblks function
    (openjp2/t1.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted bmp file. (CVE-2018-5727)

  - In OpenJPEG 2.3.0, there is an integer overflow caused by an out-of-bounds left shift in the
    opj_j2k_setup_encoder function (openjp2/j2k.c). Remote attackers could leverage this vulnerability to
    cause a denial of service via a crafted bmp file. (CVE-2018-5785)

  - In OpenJPEG 2.3.1, there is excessive iteration in the opj_t1_encode_cblks function of openjp2/t1.c.
    Remote attackers could leverage this vulnerability to cause a denial of service via a crafted bmp file.
    This issue is similar to CVE-2018-6616. (CVE-2019-12973)

  - jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a
    mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free
    may also be possible. This is related to calling opj_image_destroy twice. (CVE-2020-15389)

  - A heap-buffer overflow was found in the way openjpeg2 handled certain PNG format files. An attacker could
    use this flaw to cause an application crash or in some cases execute arbitrary code with the permission of
    the user running such an application. (CVE-2020-27814)

  - A flaw was found in OpenJPEG's encoder. This flaw allows an attacker to pass specially crafted x,y offset
    input to OpenJPEG to use during encoding. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-27823)

  - A flaw was found in OpenJPEG's encoder in the opj_dwt_calc_explicit_stepsizes() function. This flaw allows
    an attacker who can supply crafted input to decomposition levels to cause a buffer overflow. The highest
    threat from this vulnerability is to system availability. (CVE-2020-27824)

  - There's a flaw in openjpeg's t2 encoder in versions prior to 2.4.0. An attacker who is able to provide
    crafted input to be processed by openjpeg could cause a null pointer dereference. The highest impact of
    this flaw is to application availability. (CVE-2020-27842)

  - A flaw was found in OpenJPEG in versions prior to 2.4.0. This flaw allows an attacker to provide specially
    crafted input to the conversion or encoding functionality, causing an out-of-bounds read. The highest
    threat from this vulnerability is system availability. (CVE-2020-27843)

  - There's a flaw in src/lib/openjp2/pi.c of openjpeg in versions prior to 2.4.0. If an attacker is able to
    provide untrusted input to openjpeg's conversion/encoding functionality, they could cause an out-of-bounds
    read. The highest impact of this flaw is to application availability. (CVE-2020-27845)

  - Integer Overflow in OpenJPEG v2.4.0 allows remote attackers to crash the application, causing a Denial of
    Service (DoS). This occurs when the attacker uses the command line option -ImgDir on a directory that
    contains 1048576 files. (CVE-2021-29338)

  - A heap-based buffer overflow was found in openjpeg in color.c:379:42 in sycc420_to_rgb when decompressing
    a crafted .j2k file. An attacker could use this to execute arbitrary code with the permissions of the
    application compiled against openjpeg. (CVE-2021-3575)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:4251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1536552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1537758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1728505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1728509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1852869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1907513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1907516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1907523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1950101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957616");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3575");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:openjpeg2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'openjpeg2-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debuginfo-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debuginfo-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debuginfo-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debugsource-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debugsource-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-debugsource-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-devel-docs-2.4.0-4.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-debuginfo-2.4.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-debuginfo-2.4.0-4.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openjpeg2-tools-debuginfo-2.4.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjpeg2 / openjpeg2-debuginfo / openjpeg2-debugsource / etc');
}
