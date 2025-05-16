#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-311-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185345);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id("CVE-2023-42456", "CVE-2023-42465");
  script_xref(name:"IAVA", value:"2024-A-0068");

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / 15.0 / current sudo  Multiple Vulnerabilities (SSA:2023-311-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to sudo.");
  script_set_attribute(attribute:"description", value:
"The version of sudo installed on the remote host is prior to 1.9.15. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-311-01 advisory.

  - Sudo-rs, a memory safe implementation of sudo and su, allows users to not have to enter authentication at
    every sudo attempt, but instead only requiring authentication every once in a while in every terminal or
    process group. Only once a configurable timeout has passed will the user have to re-authenticate
    themselves. Supporting this functionality is a set of session files (timestamps) for each user, stored in
    `/var/run/sudo-rs/ts`. These files are named according to the username from which the sudo attempt is made
    (the origin user). An issue was discovered in versions prior to 0.2.1 where usernames containing the `.`
    and `/` characters could result in the corruption of specific files on the filesystem. As usernames are
    generally not limited by the characters they can contain, a username appearing to be a relative path can
    be constructed. For example we could add a user to the system containing the username
    `../../../../bin/cp`. When logged in as a user with that name, that user could run `sudo -K` to clear
    their session record file. The session code then constructs the path to the session file by concatenating
    the username to the session file storage directory, resulting in a resolved path of `/bin/cp`. The code
    then clears that file, resulting in the `cp` binary effectively being removed from the system. An attacker
    needs to be able to login as a user with a constructed username. Given that such a username is unlikely to
    exist on an existing system, they will also need to be able to create the users with the constructed
    usernames. The issue is patched in version 0.2.1 of sudo-rs. Sudo-rs now uses the uid for the user instead
    of their username for determining the filename. Note that an upgrade to this version will result in
    existing session files being ignored and users will be forced to re-authenticate. It also fully eliminates
    any possibility of path traversal, given that uids are always integer values. The `sudo -K` and `sudo -k`
    commands can run, even if a user has no sudo access. As a workaround, make sure that one's system does not
    contain any users with a specially crafted username. While this is the case and while untrusted users do
    not have the ability to create arbitrary users on the system, one should not be able to exploit this
    issue. (CVE-2023-42456)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.479986
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55c68614");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42456");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.9.15', 'product' : 'sudo', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach var constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
