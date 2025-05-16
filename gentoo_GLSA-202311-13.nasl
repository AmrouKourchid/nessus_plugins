#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-13.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(186267);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-30549");

  script_name(english:"GLSA-202311-13 : Apptainer: Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-13 (Apptainer: Privilege Escalation)

  - Apptainer is an open source container platform for Linux. There is an ext4 use-after-free flaw that is
    exploitable through versions of Apptainer < 1.1.0 and installations that include apptainer-suid < 1.1.8 on
    older operating systems where that CVE has not been patched. That includes Red Hat Enterprise Linux 7,
    Debian 10 buster (unless the linux-5.10 package is installed), Ubuntu 18.04 bionic and Ubuntu 20.04 focal.
    Use-after-free flaws in the kernel can be used to attack the kernel for denial of service and potentially
    for privilege escalation. Apptainer 1.1.8 includes a patch that by default disables mounting of extfs
    filesystem types in setuid-root mode, while continuing to allow mounting of extfs filesystems in non-
    setuid rootless mode using fuse2fs. Some workarounds are possible. Either do not install apptainer-suid
    (for versions 1.1.0 through 1.1.7) or set `allow setuid = no` in apptainer.conf. This requires having
    unprivileged user namespaces enabled and except for apptainer 1.1.x versions will disallow mounting of sif
    files, extfs files, and squashfs files in addition to other, less significant impacts. (Encrypted sif
    files are also not supported unprivileged in apptainer 1.1.x.). Alternatively, use the `limit containers`
    options in apptainer.conf/singularity.conf to limit sif files to trusted users, groups, and/or paths, and
    set `allow container extfs = no` to disallow mounting of extfs overlay files. The latter option by itself
    does not disallow mounting of extfs overlay partitions inside SIF files, so that's why the former options
    are also needed. (CVE-2023-30549)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-13");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905091");
  script_set_attribute(attribute:"solution", value:
"All Apptainer users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-containers/apptainer-1.1.8");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apptainer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'app-containers/apptainer',
    'unaffected' : make_list("ge 1.1.8"),
    'vulnerable' : make_list("lt 1.1.8")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Apptainer');
}
