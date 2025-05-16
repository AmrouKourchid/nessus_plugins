#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1509-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(195097);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/07");

  script_cve_id(
    "CVE-2016-8614",
    "CVE-2016-8628",
    "CVE-2016-8647",
    "CVE-2016-9587",
    "CVE-2017-7550",
    "CVE-2018-10874",
    "CVE-2020-1753",
    "CVE-2020-10744",
    "CVE-2020-14330",
    "CVE-2020-14332",
    "CVE-2020-14365",
    "CVE-2023-5764",
    "CVE-2023-6152",
    "CVE-2024-0690",
    "CVE-2024-1313"
  );
  script_xref(name:"IAVA", value:"2024-A-0126");
  script_xref(name:"IAVB", value:"2020-B-0016-S");
  script_xref(name:"IAVB", value:"2020-B-0073-S");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1509-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2024:1509-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:1509-1 advisory.

  - A flaw was found in Ansible before version 2.2.0. The apt_key module does not properly verify key
    fingerprints, allowing remote adversary to create an OpenPGP key which matches the short key ID and inject
    this key instead of the correct key. (CVE-2016-8614)

  - Ansible before version 2.2.0 fails to properly sanitize fact variables sent from the Ansible controller.
    An attacker with the ability to create special variables on the controller could execute arbitrary
    commands on Ansible clients as the user Ansible runs as. (CVE-2016-8628)

  - An input validation vulnerability was found in Ansible's mysql_user module before 2.2.1.0, which may fail
    to correctly change a password in certain circumstances. Thus the previous password would still be active
    when it should have been changed. (CVE-2016-8647)

  - Ansible before versions 2.1.4, 2.2.1 is vulnerable to an improper input validation in Ansible's handling
    of data sent from client systems. An attacker with control over a client system being managed by Ansible
    and the ability to send facts back to the Ansible server could use this flaw to execute arbitrary code on
    the Ansible server using the Ansible server privileges. (CVE-2016-9587)

  - A flaw was found in the way Ansible (2.3.x before 2.3.3, and 2.4.x before 2.4.1) passed certain parameters
    to the jenkins_plugin module. Remote attackers could use this flaw to expose sensitive information from a
    remote host's logs. This flaw was fixed by not allowing passwords to be specified in the params
    argument, and noting this in the module documentation. (CVE-2017-7550)

  - In ansible it was found that inventory variables are loaded from current working directory when running
    ad-hoc command which are under attacker's control, allowing to run arbitrary code as a result.
    (CVE-2018-10874)

  - An incomplete fix was found for the fix of the flaw CVE-2020-1733 ansible: insecure temporary directory
    when running become_user from become directive. The provided fix is insufficient to prevent the race
    condition on systems using ACLs and FUSE filesystems. Ansible Engine 2.7.18, 2.8.12, and 2.9.9 as well as
    previous versions are affected and Ansible Tower 3.4.5, 3.5.6 and 3.6.4 as well as previous versions are
    affected. (CVE-2020-10744)

  - An Improper Output Neutralization for Logs flaw was found in Ansible when using the uri module, where
    sensitive data is exposed to content and json output. This flaw allows an attacker to access the logs or
    outputs of performed tasks to read keys used in playbooks from other users within the uri module. The
    highest threat from this vulnerability is to data confidentiality. (CVE-2020-14330)

  - A flaw was found in the Ansible Engine when using module_args. Tasks executed with check mode (--check-
    mode) do not properly neutralize sensitive data exposed in the event data. This flaw allows unauthorized
    users to read this data. The highest threat from this vulnerability is to confidentiality.
    (CVE-2020-14332)

  - A flaw was found in the Ansible Engine, in ansible-engine 2.8.x before 2.8.15 and ansible-engine 2.9.x
    before 2.9.13, when installing packages using the dnf module. GPG signatures are ignored during
    installation even when disable_gpg_check is set to False, which is the default behavior. This flaw leads
    to malicious packages being installed on the system and arbitrary code executed via package installation
    scripts. The highest threat from this vulnerability is to integrity and system availability.
    (CVE-2020-14365)

  - A security flaw was found in Ansible Engine, all Ansible 2.7.x versions prior to 2.7.17, all Ansible 2.8.x
    versions prior to 2.8.11 and all Ansible 2.9.x versions prior to 2.9.7, when managing kubernetes using the
    k8s module. Sensitive parameters such as passwords and tokens are passed to kubectl from the command line,
    not using an environment variable or an input configuration file. This will disclose passwords and tokens
    from process list and no_log directive from debug module would not have any effect making these secrets
    being disclosed on stdout and log files. (CVE-2020-1753)

  - A template injection flaw was found in Ansible where a user's controller internal templating operations
    may remove the unsafe designation from template data. This issue could allow an attacker to use a
    specially crafted file to introduce templating injection when supplying templating data. (CVE-2023-5764)

  - A user changing their email after signing up and verifying it can change it without verification in
    profile settings. The configuration option verify_email_enabled will only validate email only on sign
    up. (CVE-2023-6152)

  - An information disclosure flaw was found in ansible-core due to a failure to respect the ANSIBLE_NO_LOG
    configuration in some scenarios. Information is still included in the output in certain tasks, such as
    loop items. Depending on the task, this issue may include sensitive information, such as decrypted secret
    values. (CVE-2024-0690)

  - It is possible for a user in a different organization from the owner of a snapshot to bypass authorization
    and delete a snapshot by issuing a DELETE request to /api/snapshots/<key> using its view key. This
    functionality is intended to only be available to individuals with the permission to write/edit to the
    snapshot in question, but due to a bug in the authorization logic, deletion requests issued by an
    unprivileged user in a different organization than the snapshot owner are treated as authorized. Grafana
    Labs would like to thank Ravid Mazon and Jay Chen of Palo Alto Research for discovering and disclosing
    this vulnerability. This issue affects Grafana: from 9.5.0 before 9.5.18, from 10.0.0 before 10.0.13, from
    10.1.0 before 10.1.9, from 10.2.0 before 10.2.6, from 10.3.0 before 10.3.5. (CVE-2024-1313)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1008037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1008038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1010940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1019021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1038785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1059235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222155");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035168.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-8614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-8628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-8647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-9587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6152");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1313");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9587");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7550");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-proxy-systemd-services");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ansible-2.9.27-150000.1.17.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'ansible-doc-2.9.27-150000.1.17.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'uyuni-proxy-systemd-services-4.3.12-150000.1.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'POS_Image-Graphical7-0.1.1710765237.46af599-150000.1.21.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'POS_Image-JeOS7-0.1.1710765237.46af599-150000.1.21.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ansible-2.9.27-150000.1.17.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ansible-doc-2.9.27-150000.1.17.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ansible-test-2.9.27-150000.1.17.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dracut-saltboot-0.1.1710765237.46af599-150000.1.53.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'golang-github-prometheus-promu-0.14.0-150000.3.18.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'spacecmd-4.3.27-150000.3.116.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'golang-github-prometheus-promu-0.14.0-150000.3.18.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'POS_Image-Graphical7 / POS_Image-JeOS7 / ansible / ansible-doc / etc');
}
