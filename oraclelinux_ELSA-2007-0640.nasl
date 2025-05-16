#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2007-0640.
##

include('compat.inc');

if (description)
{
  script_id(180618);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2007-4136");

  script_name(english:"Oracle Linux 5 : conga (ELSA-2007-0640)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2007-0640 advisory.

    [0.10.0-6.el5.0.1]
    - Replaced Redhat copyrighted and trademarked images in the conga-0.10.0 tarball.

    [0.10.0-6]

    - Fixed bz253783
    - Fixed bz253914 (conga doesn't allow you to reuse nfs export and nfs client resources)
    - Fixed bz254038 (Impossible to set many valid quorum disk configurations via conga)
    - Fixed bz253994 (Cannot specify multicast address for a cluster)
    - Resolves: bz253783, bz253914, bz254038, bz253994

    [0.10.0-5]

    - Fixed bz249291 (delete node task fails to do all items listed in the help document)
    - Fixed bz253341 (failure to start cluster service which had been modifed for correction)
    - Related: bz253341
    - Resolves: bz249291

    [0.10.0-4]

    - Fixed bz230451 (fence_xvm.key file is not automatically created. Should have a least a default)
    - Fixed bz249097 (allow a space as a valid password char)
    - Fixed bz250834 (ZeroDivisionError when attempting to click an empty lvm volume group)
    - Fixed bz250443 (storage name warning utility produces a storm of warnings which can lock your browser)
    - Resolves: bz249097, bz250443, bz250834
    - Related: bz230451

    [0.10.0-3]

    - Fixed bz245947 (luci/Conga cluster configuration tool not initializing cluster node members)
    - Fixed bz249641 (conga is unable to do storage operations if there is an lvm snapshot present)
    - Fixed bz249342 (unknown ricci error when adding new node to cluster)
    - Fixed bz249291 (delete node task fails to do all items listed in the help document)
    - Fixed bz249091 (RFE: tell user they are about to kill all their nodes)
    - Fixed bz249066 (AttributeError when attempting to configure a fence device)
    - Fixed bz249086 (Unable to add a new fence device to cluster)
    - Fixed bz249868 (Use of failover domain not correctly shown)
    - Resolves bz245947, bz249641, bz249342, bz249291, bz249091,
    - Resolves bz249066, bz249086, bz249868
    - Related: bz249351

    [0.10.0-2]

    - Fixed bz245202 (Conga needs to support Internet Explorer 6.0 and later)
    - Fixed bz248317 (luci sets incorrect permissions on /usr/lib64/luci and /var/lib/luci)
    - Resolves: bz245202 bz248317

    [0.10.0-1]
    - Fixed bz238655 (conga does not set the 'nodename' attribute for manual fencing)
    - Fixed bz221899 (Node log displayed in partially random order)
    - Fixed bz225782 (Need more luci service information on startup - no info written to log about failed
    start cause)
    - Fixed bz227743 (Intermittent/recurring problem - when cluster is deleted, sometimes a node is not
    affected)
    - Fixed bz227682 (saslauthd[2274]: Deprecated pam_stack module called from service 'ricci')
    - Fixed bz238726 (Conga provides no way to remove a dead node from a cluster)
    - Fixed bz239389 (conga cluster: make 'enable shared storage' the default)
    - Fixed bz239596
    - Fixed bz240034 (rpm verify fails on luci)
    - Fixed bz240361 (Conga storage UI front-end is too slow rendering storage)
    - Fixed bz241415 (Installation using Conga shows 'error' in message during reboot cycle.)
    - Fixed bz241418 (Conga tries to configurage cluster snaps, though they are not available.)
    - Fixed bz241706 (Eliminate confusion in add fence flow)
    - Fixed bz241727 (can't set user permissions in luci)
    - Fixed bz242668 (luci init script can return non-LSB-compliant return codes)
    - Fixed bz243701 (ricci init script can exit with non-LSB-compliant return codes)
    - Fixed bz244146 (Add port number to message when ricci is not started/firewalled on cluster nodes.)
    - Fixed bz244878 (Successful login results in an infinite redirection loop with MSIE)
    - Fixed bz239388 (conga storage: default VG creation should be clustered if a cluster node)
    - Fixed bz239327 (Online User Manual needs modification)
    - Fixed bz227852 (Lack of debugging information in logs - support issue)
    - Fixed bz245025 (Conga does not accept '&' character in password field for Fence configuration)
    - Fixed bz225588 (luci web app does not enforce selection of fence port)
    - Fixed bz212022 (cannot create cluster using ip addresses)
    - Fixed bz223162 (Error trying to create a new fence device for a cluster node)
    - Upgraded to the latest Plone (2.5.3)
    - Added a 'reprobe storage' button that invalidates cached storage reports
      and forces a new probe.
    - Resolves: bz238655, bz221899, bz225782, bz227682, bz227743, bz239389,
    - Resolves: bz239596, bz240034, bz240361, bz241415, bz241418, bz241706,
    - Resolves: bz241727, bz242668, bz243701, bz244146, bz244878, bz238726,
    - Resolves: bz239388, bz239327, bz227852, bz245025, bz225588, bz212022

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2007-0640.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected luci and / or ricci packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ricci");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'luci-0.10.0-6.el5.0.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ricci-0.10.0-6.el5.0.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'luci-0.10.0-6.el5.0.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ricci-0.10.0-6.el5.0.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'luci / ricci');
}
