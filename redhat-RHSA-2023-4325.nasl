#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4325. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179051);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-3347");
  script_xref(name:"RHSA", value:"2023:4325");
  script_xref(name:"IAVA", value:"2023-A-0376-S");

  script_name(english:"RHEL 9 : samba (RHSA-2023:4325)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for samba.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2023:4325 advisory.

    Samba is an open-source implementation of the Server Message Block (SMB) protocol and the related Common
    Internet File System (CIFS) protocol, which allow PC-compatible machines to share files, printers, and
    various information.

    Security Fix(es):

    * samba: SMB2 packet signing is not enforced when server signing = required is set (CVE-2023-3347)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * The trust relationship between this workstation and the primary domain failed (BZ#2223600)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_4325.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47838250");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223600");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4325");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL samba package based on the guidance in RHSA-2023:4325.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnetapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dcerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-ldb-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-usershares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winexe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.2'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.2/ppc64le/appstream/os',
      'content/e4s/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.2/ppc64le/baseos/os',
      'content/e4s/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/e4s/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/debug',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/os',
      'content/e4s/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/os',
      'content/e4s/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/appstream/debug',
      'content/eus/rhel9/9.2/ppc64le/appstream/os',
      'content/eus/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/baseos/debug',
      'content/eus/rhel9/9.2/ppc64le/baseos/os',
      'content/eus/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/eus/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/resilientstorage/debug',
      'content/eus/rhel9/9.2/s390x/resilientstorage/os',
      'content/eus/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/os',
      'content/eus/rhel9/9.2/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ctdb-4.17.5-103.el9_2', 'sp':'2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ctdb-4.17.5-103.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ctdb-4.17.5-103.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnetapi-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnetapi-devel-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-dc-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-devel-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-test-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-libs-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-libs-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-tools-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-libs-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dcerpc-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-krb5-printing-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-ldb-ldap-modules-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-pidl-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-libs-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-tools-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-usershares-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-vfs-iouring-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.17.5-103.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winexe-4.17.5-103.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/baseos/debug',
      'content/dist/rhel9/9.1/ppc64le/baseos/os',
      'content/dist/rhel9/9.1/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.1/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/baseos/debug',
      'content/dist/rhel9/9.1/s390x/baseos/os',
      'content/dist/rhel9/9.1/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.1/s390x/codeready-builder/os',
      'content/dist/rhel9/9.1/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.1/s390x/resilientstorage/os',
      'content/dist/rhel9/9.1/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/baseos/debug',
      'content/dist/rhel9/9.1/x86_64/baseos/os',
      'content/dist/rhel9/9.1/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.1/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/baseos/debug',
      'content/dist/rhel9/9.2/ppc64le/baseos/os',
      'content/dist/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.2/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/baseos/debug',
      'content/dist/rhel9/9.2/s390x/baseos/os',
      'content/dist/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.2/s390x/codeready-builder/os',
      'content/dist/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.2/s390x/resilientstorage/os',
      'content/dist/rhel9/9.2/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/baseos/debug',
      'content/dist/rhel9/9.2/x86_64/baseos/os',
      'content/dist/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.2/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/baseos/debug',
      'content/dist/rhel9/9.3/ppc64le/baseos/os',
      'content/dist/rhel9/9.3/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.3/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/baseos/debug',
      'content/dist/rhel9/9.3/s390x/baseos/os',
      'content/dist/rhel9/9.3/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.3/s390x/codeready-builder/os',
      'content/dist/rhel9/9.3/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.3/s390x/resilientstorage/os',
      'content/dist/rhel9/9.3/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/baseos/debug',
      'content/dist/rhel9/9.3/x86_64/baseos/os',
      'content/dist/rhel9/9.3/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.3/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/baseos/debug',
      'content/dist/rhel9/9.4/ppc64le/baseos/os',
      'content/dist/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.4/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/baseos/debug',
      'content/dist/rhel9/9.4/s390x/baseos/os',
      'content/dist/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.4/s390x/codeready-builder/os',
      'content/dist/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.4/s390x/resilientstorage/os',
      'content/dist/rhel9/9.4/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/baseos/debug',
      'content/dist/rhel9/9.4/x86_64/baseos/os',
      'content/dist/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.4/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/baseos/debug',
      'content/dist/rhel9/9.5/ppc64le/baseos/os',
      'content/dist/rhel9/9.5/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9.5/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/baseos/debug',
      'content/dist/rhel9/9.5/s390x/baseos/os',
      'content/dist/rhel9/9.5/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.5/s390x/codeready-builder/os',
      'content/dist/rhel9/9.5/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/resilientstorage/debug',
      'content/dist/rhel9/9.5/s390x/resilientstorage/os',
      'content/dist/rhel9/9.5/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/baseos/debug',
      'content/dist/rhel9/9.5/x86_64/baseos/os',
      'content/dist/rhel9/9.5/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/os',
      'content/dist/rhel9/9.5/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/baseos/debug',
      'content/dist/rhel9/9/ppc64le/baseos/os',
      'content/dist/rhel9/9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/resilientstorage/debug',
      'content/dist/rhel9/9/ppc64le/resilientstorage/os',
      'content/dist/rhel9/9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/resilientstorage/debug',
      'content/dist/rhel9/9/s390x/resilientstorage/os',
      'content/dist/rhel9/9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ctdb-4.17.5-103.el9_2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ctdb-4.17.5-103.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ctdb-4.17.5-103.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnetapi-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnetapi-devel-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-dc-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-devel-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-samba-test-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-libs-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-libs-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-tools-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-libs-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dcerpc-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-krb5-printing-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-ldb-ldap-modules-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-pidl-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-libs-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-tools-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-usershares-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-vfs-iouring-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.17.5-103.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winexe-4.17.5-103.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnetapi / libnetapi-devel / libsmbclient / etc');
}
