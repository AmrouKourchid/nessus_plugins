#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0414 and 
# Oracle Linux Security Advisory ELSA-2011-0414 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68246);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2011-1011");
  script_bugtraq_id(46510);
  script_xref(name:"RHSA", value:"2011:0414");

  script_name(english:"Oracle Linux 6 : policycoreutils (ELSA-2011-0414)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2011-0414 advisory.

    policycoreutils:

    [2.0.83-19.8]
    - Fix seunshare to work with /tmp content when SELinux context is not provided
    Resolves: #679689

    [2.0.83-19.7]
    - put back correct chcon
    - Latest fixes for seunshare

    [2.0.83-19.6]
    - Fix rsync command to work if the directory is old.
    - Fix all tests
    Resolves: #679689

    [2.0.83-19.5]
    - Add requires rsync and  fix man page for seunshare

    [2.0.83-19.4]
    - fix to sandbox
      - Fix seunshare to use more secure handling of /tmp
        - Rewrite seunshare to make sure /tmp is mounted stickybit owned by root
       - Change to allow sandbox to run on nfs homedirs, add start python script
       - change default location of HOMEDIR in sandbox to /tmp/.sandbox_home_*
       - Move seunshare to sandbox package
       - Fix sandbox to show correct types in  usage statement

    selinux-policy:

    [3.7.19-54.0.1.el6_0.5]
    - Allow ocfs2 to be mounted with file_t type.

    [3.7.19-54.el6_0.5]
    - seunshare needs to be able to mounton nfs/cifs/fusefs homedirs
    Resolves: #684918

    [3.7.19-54.el6_0.4]
    - Fix to sandbox
            * selinux-policy fixes for policycoreutils sandbox changes
                    - Fix seunshare to use more secure handling of /tmp
                    - Change to allow sandbox to run on nfs homedirs, add start python script

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0414.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'policycoreutils-2.0.83-19.8.el6_0', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-gui-2.0.83-19.8.el6_0', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-newrole-2.0.83-19.8.el6_0', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-python-2.0.83-19.8.el6_0', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-sandbox-2.0.83-19.8.el6_0', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-3.7.19-54.0.1.el6_0.5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-doc-3.7.19-54.0.1.el6_0.5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-minimum-3.7.19-54.0.1.el6_0.5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-mls-3.7.19-54.0.1.el6_0.5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-targeted-3.7.19-54.0.1.el6_0.5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-2.0.83-19.8.el6_0', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-gui-2.0.83-19.8.el6_0', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-newrole-2.0.83-19.8.el6_0', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-python-2.0.83-19.8.el6_0', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'policycoreutils-sandbox-2.0.83-19.8.el6_0', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-3.7.19-54.0.1.el6_0.5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-doc-3.7.19-54.0.1.el6_0.5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-minimum-3.7.19-54.0.1.el6_0.5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-mls-3.7.19-54.0.1.el6_0.5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'selinux-policy-targeted-3.7.19-54.0.1.el6_0.5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'policycoreutils / policycoreutils-gui / policycoreutils-newrole / etc');
}
