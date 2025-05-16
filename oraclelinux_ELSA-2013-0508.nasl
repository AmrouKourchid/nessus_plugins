#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0508 and 
# Oracle Linux Security Advisory ELSA-2013-0508 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68747);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2013-0219", "CVE-2013-0220");
  script_bugtraq_id(57539);
  script_xref(name:"RHSA", value:"2013:0508");

  script_name(english:"Oracle Linux 6 : sssd (ELSA-2013-0508)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-0508 advisory.

    [1.9.2-82]
    - Resolves: rhbz#888614 - Failure in memberof can lead to failed
                              database update

    [1.9.2-81]
    - Resolves: rhbz#903078 - TOCTOU race conditions by copying
                              and removing directory trees

    [1.9.2-80]
    - Resolves: rhbz#903078 - Out-of-bounds read flaws in
                              autofs and ssh services responders

    [1.9.2-79]
    - Resolves: rhbz#902716 - Rule mismatch isn't noticed before smart refresh
                              on ppc64 and s390x

    [1.9.2-78]
    - Resolves: rhbz#896476 - SSSD should warn when pam_pwd_expiration_warning
                              value is higher than passwordWarning LDAP attribute.

    [1.9.2-77]
    - Resolves: rhbz#902436 - possible segfault when backend callback is removed

    [1.9.2-76]
    - Resolves: rhbz#895132 - Modifications using sss_usermod tool are not
                              reflected in memory cache

    [1.9.2-75]
    - Resolves: rhbz#894302 - sssd fails to update to changes on autofs maps

    [1.9.2-74]
    - Resolves: rhbz894381 - memory cache is not updated after user is deleted
                             from ldb cache

    [1.9.2-73]
    - Resolves: rhbz895615 - ipa-client-automount: autofs failed in s390x and
                             ppc64 platform

    [1.9.2-72]
    - Resolves: rhbz#894997 - sssd_be crashes looking up members with groups
                              outside the nesting limit

    [1.9.2-71]
    - Resolves: rhbz#895132 - Modifications using sss_usermod tool are not
                              reflected in memory cache

    [1.9.2-70]
    - Resolves: rhbz#894428 - wrong filter for autofs maps in sss_cache

    [1.9.2-69]
    - Resolves: rhbz#894738 - Failover to ldap_chpass_backup_uri doesn't work

    [1.9.2-68]
    - Resolves: rhbz#887961 - AD provider: getgrgid removes nested group
                              memberships

    [1.9.2-67]
    - Resolves: rhbz#878583 - IPA Trust does not show secondary groups for AD
                              Users for commands like id and getent

    [1.9.2-66]
    - Resolves: rhbz#874579 - sssd caching not working as expected for selinux
                              usermap contexts

    [1.9.2-65]
    - Resolves: rhbz#892197 - Incorrect principal searched for in keytab

    [1.9.2-64]
    - Resolves: rhbz#891356 - Smart refresh doesn't notice 'defaults' addition
                              with OpenLDAP

    [1.9.2-63]
    - Resolves: rhbz#878419 - sss_userdel doesn't remove entries from in-memory
                              cache

    [1.9.2-62]
    - Resolves: rhbz#886848 - user id lookup fails for case sensitive users
                              using proxy provider

    [1.9.2-61]
    - Resolves: rhbz#890520 - Failover to krb5_backup_kpasswd doesn't work

    [1.9.2-60]
    - Resolves: rhbz#874618 - sss_cache: fqdn not accepted

    [1.9.2-59]
    - Resolves: rhbz#889182 - crash in memory cache

    [1.9.2-58]
    - Resolves: rhbz#889168 - krb5 ticket renewal does not read the renewable
                              tickets from cache

    [1.9.2-57]
    - Resolves: rhbz#886091 - Disallow root SSH public key authentication
    - Add default section to switch statement (Related: rhbz#884666)

    [1.9.2-56]
    - Resolves: rhbz#886038 - sssd components seem to mishandle sighup

    [1.9.2-55]
    - Resolves: rhbz#888800 - Memory leak in new memcache initgr cleanup function

    [1.9.2-54]
    - Resolves: rhbz#888614 - Failure in memberof can lead to failed database
                              update

    [1.9.2-53]
    - Resolves: rhbz#885078 - sssd_nss crashes during enumeration if the
                              enumeration is taking too long

    [1.9.2-52]
    - Related: rhbz#875851 - sysdb upgrade failed converting db to 0.11
    - Include more debugging during the sysdb upgrade

    [1.9.2-51]
    - Resolves: rhbz#877972 - ldap_sasl_authid no longer accepts full principal

    [1.9.2-50]
    - Resolves: rhbz#870045 - always reread the master map from LDAP
    - Resolves: rhbz#876531 - sss_cache does not work for automount maps

    [1.9.2-49]
    - Resolves: rhbz#884666 - sudo: if first full refresh fails, schedule
                              another first full refresh

    [1.9.2-48]
    - Resolves: rhbz#880956 - Primary server status is not always reset after
                              failover to backup server happened
    - Silence a compilation warning in the memberof plugin (Related: rhbz#877974)
    - Do not steal resolv result on error (Related: rhbz#882076)

    [1.9.2-47]
    - Resolves: rhbz#882923 - Negative cache timeout is not working for proxy
                              provider

    [1.9.2-46]
    - Resolves: rhbz#884600 - ldap_chpass_uri failover fails on using same
                              hostname

    [1.9.2-45]
    - Resolves: rhbz#858345 - pam_sss(crond:account): Request to sssd
                              failed. Timer expired

    [1.9.2-44]
    - Resolves: rhbz#878419 - sss_userdel doesn't remove entries from in-memory
                              cache

    [1.9.2-43]
    - Resolves: rhbz#880176 - memberUid required for primary groups to match
                              sudo rule

    [1.9.2-42]
    - Resolves: rhbz#885105 - sudo denies access with disabled
                              ldap_sudo_use_host_filter

    [1.9.2-41]
    - Resolves: rhbz#883408 - Option ldap_sudo_include_regexp named incorrectly

    [1.9.2-40]
    - Resolves: rhbz#880546 - krb5_kpasswd failover doesn't work
    - Fix the error handler in sss_mc_create_file (Related: #789507)

    [1.9.2-39]
    - Resolves: rhbz#882221 - Offline sudo denies access with expired
                              entry_cache_timeout
    - Fix several bugs found by Coverity and clang:
    - Check the return value of diff_gid_lists (Related: #869071)
    - Move misplaced sysdb assignment (Related: #827606)
    - Remove dead assignment (Related: #827606)
    - Fix copy-n-paste error in the memberof plugin (Related: #877974)

    [1.9.2-38]
    - Resolves: rhbz#882923 - Negative cache timeout is not working for proxy
                              provider
    - Link sss_ssh_authorizedkeys and sss_ssh_knowhostsproxy with the client
      libraries (Related: #870060)
    - Move sss_ssh_knownhosts documentation to the correct section
      (Related: #870060)

    [1.9.2-37]
    - Resolves: rhbz#884480 - user is not removed from group membership during
                              initgroups
    - Fix incorrect synchronization in mmap cache (Related: #789507)

    [1.9.2-36]
    - Resolves: rhbz#883336 - sssd crashes during start if id_provider is
                              not mentioned

    [1.9.2-35]
    - Resolves: rhbz#882290 - arithmetic bug in the SSSD causes netgroup
                              midpoint refresh to be always set to 10 seconds

    [1.9.2-34]
    - Resolves: rhbz#877974 - updating top-level group does not reflect ghost
                              members correctly
    - Resolves: rhbz#880159 - delete operation is not implemented for ghost users

    [1.9.2-33]
    - Resolves: rhbz#881773 - mmap cache needs update after db changes

    [1.9.2-32]
    - Resolves: rhbz#875677 - password expiry warning message doesn't appear
                              during auth
    - Fix potential NULL dereference when skipping built-in AD groups
      (Related: rhbz#874616)
    - Add missing parameter to DEBUG message (Related: rhbz#829742)

    [1.9.2-31]
    - Resolves: rhbz#882076 - SSSD crashes when c-ares returns success but an
                              empty hostent during the DNS update
    - Do not version libsss_sudo, it's not supposed to be linked against, but
      dlopened (Related: rhbz#761573)

    [1.9.2-30]
    - Resolves: rhbz#880140 - sssd hangs at startup with broken configurations

    [1.9.2-29]
    - Resolves: rhbz#878420 - SIGSEGV in IPA provider when ldap_sasl_authid is not set

    [1.9.2-28]
    - Resolves: rhbz#874616 - Silence the DEBUG messages when ID mapping code
                              skips a built-in group

    [1.9.2-27]
    - Resolves: rhbz#824244 - sssd does not warn into sssd.log for broken
                              configurations

    [1.9.2-26]
    - Resolves: rhbz#874673 - user id lookup fails using proxy provider
    - Fix a possibly uninitialized variable in the LDAP provider
    - Related: rhbz#877130

    [1.9.2-25]
    - Resolves: rhbz#878262 - ipa password auth failing for user principal
                              name when shorter than IPA Realm name
    - Resolves: rhbz#871843 - Nested groups are not retrieved appropriately
                              from cache

    [1.9.2-24]
    - Resolves: rhbz#870238 - IPA client cannot change AD Trusted User password

    [1.9.2-23]
    - Resolves: rhbz#877972 - ldap_sasl_authid no longer accepts full principal

    [1.9.2-22]
    - Resolves: rhbz#861075 - SSSD_NSS failure to gracefully restart
                              after sbus failure

    [1.9.2-21]
    - Resolves: rhbz#877354 - ldap_connection_expire_timeout doesn't expire
                              ldap connections

    [1.9.2-20]
    - Related: rhbz#877126 - Bump the release tag

    [1.9.2-20]
    - Resolves: rhbz#877126 - subdomains code does not save the proper
                              user/group name

    [1.9.2-19]
    - Resolves: rhbz#877130 - LDAP provider fails to save empty groups
    - Related: rhbz#869466 - check the return value of waitpid()

    [1.9.2-18]
    - Resolves: rhbz#870039 - sss_cache says 'Wrong DB version'

    [1.9.2-17]
    - Resolves: rhbz#875740 - 'defaults' entry ignored

    [1.9.2-16]
    - Resolves: rhbz#875738 - offline authentication failure always returns
                              System Error

    [1.9.2-15]
    - Resolves: rhbz#875851 - sysdb upgrade failed converting db to 0.11

    [1.9.2-14]
    - Resolves: rhbz#870278 -  ipa client setup should configure host properly
                               in a trust is in place

    [1.9.2-13]
    - Resolves: rhbz#871160 - sudo failing for ad trusted user in IPA environment

    [1.9.2-12]
    - Resolves: rhbz#870278 -  ipa client setup should configure host properly
                               in a trust is in place

    [1.9.2-11]
    - Resolves: rhbz#869678 - sssd not granting access for AD trusted user in HBAC rule

    [1.9.2-10]
    - Resolves: rhbz#872180 - subdomains: Invalid sub-domain request type
    - Related: rhbz#867933 - invalidating the memcache with sss_cache doesn't work
                             if the sssd is not running

    [1.9.2-9]
    - Resolves: rhbz#873988 - Man page issue to list 'force_timeout' as an
                              option for the [sssd] section

    [1.9.2-8]
    - Resolves: rhbz#873032 - Move sss_cache to the main subpackage

    [1.9.2-7]
    - Resolves: rhbz#873032 - Move sss_cache to the main subpackage
    - Resolves: rhbz#829740 - Init script reports complete before sssd is actually
                              working
    - Resolves: rhbz#869466 - SSSD starts multiple processes due to syntax error in
                              ldap_uri
    - Resolves: rhbz#870505 - sss_cache: Multiple domains not handled properly
    - Resolves: rhbz#867933 - invalidating the memcache with sss_cache doesn't work
                              if the sssd is not running
    - Resolves: rhbz#872110 - User appears twice on looking up a nested group

    [1.9.2-6]
    - Resolves: rhbz#871576 - sssd does not resolve group names from AD
    - Resolves: rhbz#872324 - pam: fd leak when writing the selinux login file
                              in the pam responder
    - Resolves: rhbz#871424 - authconfig chokes on sssd.conf with chpass_provider
                              directive

    [1.9.2-5]
    - Do not send SIGKILL to service right after sending SIGTERM
    - Resolves: #771975
    - Fix the initial sudo smart refresh
    - Resolves: #869013
    - Implement password authentication for users from trusted domains
    - Resolves: #869071
    - LDAP child crashed with a wrong keytab
    - Resolves: #869150
    - The sssd_nss process grows the memory consumption over time
    - Resolves: #869443

    [1.9.2-4]
    - BuildRequire selinux-policy so that selinux login support is built in
    - Resolves: #867932

    [1.9.2-3]
    - Do not segfault if namingContexts contain no values or multiple values
    - Resolves: rhbz#866542

    [1.9.2-2]
    - Fix the 'ca' translation of the sssd-simple manual page
    - Related: rhbz#827606 - Rebase SSSD to 1.9 in 6.4

    [1.9.2-1]
    - New upstream release 1.9.2

    [1.9.1-1]
    - Rebase to 1.9.1

    [1.9.0-3]
    - Require the latest libldb

    [1.9.0-2]
    - Rebase to 1.9.0
    - Resolves: rhbz#827606 - Rebase SSSD to 1.9 in 6.4

    [1.9.0-1.rc1]
    - Rebase to 1.9.0 RC1
    - Resolves: rhbz#827606 - Rebase SSSD to 1.9 in 6.4
    - Bump the selinux-policy version number to pull in required fixes

    [1.8.0-33]
    - Resolves: rhbz#840089 - Update the shadowLastChange attribute
                              with days since the Epoch, not seconds

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0508.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0219");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-0220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-tools");
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
    {'reference':'libipa_hbac-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-python-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-devel-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.9.2-82.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-python-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-devel-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.9.2-82.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa_hbac / libipa_hbac-devel / libipa_hbac-python / etc');
}
