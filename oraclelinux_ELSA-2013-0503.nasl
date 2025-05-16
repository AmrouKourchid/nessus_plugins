#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0503 and 
# Oracle Linux Security Advisory ELSA-2013-0503 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68743);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2012-4450");
  script_bugtraq_id(55690);
  script_xref(name:"RHSA", value:"2013:0503");

  script_name(english:"Oracle Linux 6 : 389-ds-base (ELSA-2013-0503)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2013-0503 advisory.

    [1.2.11.15-11]
    - Resolves: Bug 896256 - updating package touches configuration files

    [1.2.11.15-10]
    - Resolves: Bug 889083 - For modifiersName/internalModifiersName feature, internalModifiersname is not
    working for DNA plugin

    [1.2.11.15-9]
    - Resolves: Bug 891930 - DNA plugin no longer reports additional info when range is depleted

    [1.2.11.15-8]
    - Resolves: Bug 887855 - RootDN Access Control plugin is missing after upgrade from RHEL63 to RHEL64

    [1.2.11.15-7]
    - Resolves: Bug 830355 - [RFE] improve cleanruv functionality
    - Resolves: Bug 876650 - Coverity revealed defects
    - Ticket #20 - [RFE] Allow automember to work on entries that have already been added (Bug 768084)
    - Resolves: Bug 834074 - [RFE] Disable replication agreements
    - Resolves: Bug 878111 - ns-slapd segfaults if it cannot rename the logs

    [1.2.11.15-6]
    - Resolves: Bug 880305 - spec file missing dependencies for x86_64 6ComputeNode
    -   use perl-Socket6 on RHEL6

    [1.2.11.15-5]
    - Resolves: Bug 880305 - spec file missing dependencies for x86_64 6ComputeNode

    [1.2.11.15-4]
    - Resolves: Bug 868841 - Newly created users with organizationalPerson objectClass fails to sync from AD
    to DS with missing attribute error
    - Resolves: Bug 868853 - Winsync: DS error logs report wrong version of Windows AD when winsync is
    configured.
    - Resolves: Bug 875862 - crash in DNA if no dnamagicregen is specified
    - Resolves: Bug 876694 - RedHat Directory Server crashes (segfaults) when moving ldap entry
    - Resolves: Bug 876727 - Search with a complex filter including range search is slow
    - Ticket #495 - internalModifiersname not updated by DNA plugin (Bug 834053)

    [1.2.11.15-3]
    - Resolves: Bug 870158 - slapd entered to infinite loop during new index addition
    - Resolves: Bug 870162 - Cannot abandon simple paged result search
    - c970af0 Coverity defects
    - 1ac087a Fixing compiler warnings in the posix-winsync plugin
    - 2f960e4 Coverity defects
    - Ticket #491 - multimaster_extop_cleanruv returns wrong error codes

    [1.2.11.15-2]
    - Resolves: Bug 834063 [RFE] enable attribute that tracks when a password was last set on an entry in the
    LDAP store; Ticket #478 passwordTrackUpdateTime stops working with subtree password policies
    - Resolves: Bug 847868 [RFE] support posix schema for user and group sync; Ticket #481 expand nested posix
    groups
    - Resolves: Bug 860772 Change on SLAPI_MODRDN_NEWSUPERIOR is not evaluated in acl
    - Resolves: Bug 863576 Dirsrv deadlock locking up IPA
    - Resolves: Bug 864594 anonymous limits are being applied to directory manager

    [1.2.11.15-1]
    - Resolves: Bug 856657 dirsrv init script returns 0 even when few or all instances fail to start
    - Resolves: Bug 858580 389 prevents from adding a posixaccount with userpassword after schema reload

    [1.2.11.14-1]
    - Resolves: Bug 852202 Ipa master system initiated more than a dozen simultaneous replication sessions,
    shut itself down and wiped out its db
    - Resolves: Bug 855438 CLEANALLRUV task gets stuck on winsync replication agreement

    [1.2.11.13-1]
    - Resolves: Bug 847868 [RFE] support posix schema for user and group sync
    -  fix upgrade issue with plugin config schema
    -  posix winsync has default plugin precedence of 25

    [1.2.11.12-1]
    - Resolves: Bug 800051 Rebase 389-ds-base to 1.2.11
    - Resolves: Bug 742054 SASL/PLAIN binds do not work
    - Resolves: Bug 742381 MOD operations with chained delete/add get back error 53 on backend config
    - Resolves: Bug 746642 [RFE] define pam_passthru service per subtree
    - Resolves: Bug 757836 logconv.pl restarts count on conn=0 instead of conn=1
    - Resolves: Bug 768084 [RFE] Allow automember to work on entries that have already been added
    - Resolves: Bug 782975 krbExtraData is being null modified and replicated on each ssh login
    - Resolves: Bug 803873 Sync with group attribute containing () fails
    - Resolves: Bug 818762 winsync should not delete entry that appears to be out of scope
    - Resolves: Bug 830001 unhashed#user#password visible after changing password [rhel-6.4]
    - Resolves: Bug 830256 Audit log - clear text password in user changes
    - Resolves: Bug 830331 ns-slapd exits/crashes if /var fills up
    - Resolves: Bug 830334 Invalid chaining config triggers a disk full error and shutdown
    - Resolves: Bug 830335 restore of replica ldif file on second master after deleting two records shows only
    1 deletion
    - Resolves: Bug 830336 db deadlock return should not log error
    - Resolves: Bug 830337 usn + mmr = deletions are not replicated
    - Resolves: Bug 830338 Change DS to purge ticket from krb cache in case of authentication error
    - Resolves: Bug 830340 Make the CLEANALLRUV task one step
    - Resolves: Bug 830343 managed entry sometimes doesn't delete the managed entry
    - Resolves: Bug 830344 [RFE] Improve replication agreement status messages
    - Resolves: Bug 830346 ADD operations not in audit log
    - Resolves: Bug 830347 389 DS does not support multiple paging controls on a single connection
    - Resolves: Bug 830348 Slow shutdown when you have 100+ replication agreements
    - Resolves: Bug 830349 cannot use & in a sasl map search filter
    - Resolves: Bug 830353 valgrind reported memleaks and mem errors
    - Resolves: Bug 830355 [RFE] improve cleanruv functionality
    - Resolves: Bug 830356 coverity 12625-12629 - leaks, dead code, unchecked return
    - Resolves: Bug 832560 [abrt] 389-ds-base-1.2.10.6-1.fc16: slapi_attr_value_cmp: Process /usr/sbin/ns-
    slapd was killed by signal 11 (SIGSEGV)
    - Resolves: Bug 833202 transaction retries need to be cache aware
    - Resolves: Bug 833218 ldapmodify returns Operations error
    - Resolves: Bug 833222 memberOf attribute and plugin behaviour between sub-suffixes
    - Resolves: Bug 834046 [RFE] Add nsTLS1 attribute to schema and objectclass nsEncryptionConfig
    - Resolves: Bug 834047 Fine Grained Password policy: if passwordHistory is on, deleting the password
    fails.
    - Resolves: Bug 834049 [RFE] Add schema for DNA plugin
    - Resolves: Bug 834052 [RFE] limiting Directory Manager (nsslapd-rootdn) bind access by source host (e.g.
    127.0.0.1)
    - Resolves: Bug 834053 [RFE] Plugins - ability to control behavior of modifyTimestamp/modifiersName
    - Resolves: Bug 834054 Should only update modifyTimestamp/modifiersName on MODIFY ops
    - Resolves: Bug 834056 Automembership plugin fails in a MMR setup, if data and config area mixed in the
    plugin configuration
    - Resolves: Bug 834057 ldap-agent crashes on start with signal SIGSEGV
    - Resolves: Bug 834058 [RFE] logconv.pl : use of getopts to parse commandline options
    - Resolves: Bug 834060 passwordMaxFailure should lockout password one sooner - and should be configurable
    to avoid regressions
    - Resolves: Bug 834061 [RFE] RHDS: Implement SO_KEEPALIVE in network calls.
    - Resolves: Bug 834063 [RFE] enable attribute that tracks when a password was last set on an entry in the
    LDAP store
    - Resolves: Bug 834064 dnaNextValue gets incremented even if the user addition fails
    - Resolves: Bug 834065 Adding Replication agreement should complain if required nsds5ReplicaCredentials
    not supplied
    - Resolves: Bug 834074 [RFE] Disable replication agreements
    - Resolves: Bug 834075 logconv.pl reporting unindexed search with different search base than shown in
    access logs
    - Resolves: Bug 835238 Account Usability Control Not Working
    - Resolves: Bug 836386 slapi_ldap_bind() doesn't check bind results
    - Resolves: Bug 838706 referint modrdn not working if case is different
    - Resolves: Bug 840153 Impossible to rename entry (modrdn) with Attribute Uniqueness plugin enabled
    - Resolves: Bug 841600 Referential integrity plug-in does not work when update interval is not zero
    - Resolves: Bug 842437 dna memleak reported by valgrind
    - Resolves: Bug 842438 Report during startup if nsslapd-cachememsize is too small
    - Resolves: Bug 842440 memberof performance enhancement
    - Resolves: Bug 842441 'Server is unwilling to perform' when running ldapmodify on nsds5ReplicaStripAttrs
    - Resolves: Bug 847868 [RFE] support posix schema for user and group sync
    - Resolves: Bug 850683 nsds5ReplicaEnabled can be set with any invalid values.
    - Resolves: Bug 852087 [RFE] add attribute nsslapd-readonly so we can reference it in acis
    - Resolves: Bug 852088 server to server ssl client auth broken with latest openldap
    - Resolves: Bug 852839 variable dn should not be used in ldbm_back_delete

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0503.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected 389-ds-base, 389-ds-base-devel and / or 389-ds-base-libs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'389-ds-base-1.2.11.15-11.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'389-ds-base-devel-1.2.11.15-11.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'389-ds-base-libs-1.2.11.15-11.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'389-ds-base-1.2.11.15-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'389-ds-base-devel-1.2.11.15-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'389-ds-base-libs-1.2.11.15-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '389-ds-base / 389-ds-base-devel / 389-ds-base-libs');
}
