#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202310-22.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(184073);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/01");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-21996",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-31607",
    "CVE-2022-22934",
    "CVE-2022-22935",
    "CVE-2022-22936",
    "CVE-2022-22941",
    "CVE-2022-22967"
  );

  script_name(english:"GLSA-202310-22 : Salt: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202310-22 (Salt: Multiple Vulnerabilities)

  - An issue was discovered in SaltStack Salt before 3002.5. The minion's restartcheck is vulnerable to
    command injection via a crafted process name. This allows for a local privilege escalation by any user
    able to create a files on the minion in a non-blacklisted directory. (CVE-2020-28243)

  - In SaltStack Salt before 3002.5, authentication to VMware vcenter, vsphere, and esxi servers (in the
    vmware.py files) does not always validate the SSL/TLS certificate. (CVE-2020-28972)

  - In SaltStack Salt before 3002.5, when authenticating to services using certain modules, the SSL
    certificate is not always validated. (CVE-2020-35662)

  - In SaltStack Salt before 3002.5, eauth tokens can be used once after expiration. (They might be used to
    run command against the salt master or minions.) (CVE-2021-3144)

  - An issue was discovered in SaltStack Salt before 3002.5. Sending crafted web requests to the Salt API can
    result in salt.utils.thin.gen_thin() command injection because of different handling of single versus
    double quotes. This is related to salt/utils/thin.py. (CVE-2021-3148)

  - An issue was discovered in SaltStack Salt before 3002.5. The salt-api's ssh client is vulnerable to a
    shell injection by including ProxyCommand in an argument, or via ssh_options provided in an API request.
    (CVE-2021-3197)

  - An issue was discovered in SaltStack Salt before 3003.3. A user who has control of the source, and
    source_hash URLs can gain full file system access as root on a salt minion. (CVE-2021-21996)

  - An issue was discovered in through SaltStack Salt before 3002.5. salt-api does not honor eauth credentials
    for the wheel_async client. Thus, an attacker can remotely run any wheel modules on the master.
    (CVE-2021-25281)

  - An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method
    is vulnerable to directory traversal. (CVE-2021-25282)

  - An issue was discovered in through SaltStack Salt before 3002.5. The jinja renderer does not protect
    against server side template injection attacks. (CVE-2021-25283)

  - An issue was discovered in through SaltStack Salt before 3002.5. salt.modules.cmdmod can log credentials
    to the info or error log level. (CVE-2021-25284)

  - In SaltStack Salt 2016.9 through 3002.6, a command injection vulnerability exists in the snapper module
    that allows for local privilege escalation on a minion. The attack requires that a file is created with a
    pathname that is backed up by snapper, and that the master calls the snapper.diff function (which executes
    popen unsafely). (CVE-2021-31607)

  - An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. Salt Masters do not
    sign pillar data with the minion's public key, which can result in attackers substituting arbitrary pillar
    data. (CVE-2022-22934)

  - An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. A minion
    authentication denial of service can cause a MiTM attacker to force a minion process to stop by
    impersonating a master. (CVE-2022-22935)

  - An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. Job publishes and
    file server replies are susceptible to replay attacks, which can result in an attacker replaying job
    publishes causing minions to run old jobs. File server replies can also be re-played. A sufficient craft
    attacker could gain root access on minion under certain scenarios. (CVE-2022-22936)

  - An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. When configured as a
    Master-of-Masters, with a publisher_acl, if a user configured in the publisher_acl targets any minion
    connected to the Syndic, the Salt Master incorrectly interpreted no valid targets as valid, allowing
    configured users to target any of the minions connected to the syndic with their configured commands. This
    requires a syndic master combined with publisher_acl configured on the Master-of-Masters, allowing users
    specified in the publisher_acl to bypass permissions, publishing authorized commands to any configured
    minion. (CVE-2022-22941)

  - An issue was discovered in SaltStack Salt in versions before 3002.9, 3003.5, 3004.2. PAM auth fails to
    reject locked accounts, which allows a previously authorized user whose account is locked still run Salt
    commands when their account is locked. This affects both local shell accounts with an active session and
    salt-api users that authenticate via PAM eauth. (CVE-2022-22967)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202310-22");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=767919");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=812440");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836365");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=855962");
  script_set_attribute(attribute:"solution", value:
"All Salt users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-admin/salt-3004.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:salt");
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
    'name' : 'app-admin/salt',
    'unaffected' : make_list("ge 3004.2"),
    'vulnerable' : make_list("lt 3004.2")
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
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Salt');
}
