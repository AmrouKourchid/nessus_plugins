#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASANSIBLE2-2023-008.
##

include('compat.inc');

if (description)
{
  script_id(181996);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2020-1733",
    "CVE-2020-1735",
    "CVE-2020-1740",
    "CVE-2020-1746",
    "CVE-2020-1753",
    "CVE-2020-10684",
    "CVE-2020-10685",
    "CVE-2020-10691"
  );
  script_xref(name:"IAVB", value:"2019-B-0092-S");
  script_xref(name:"IAVB", value:"2020-B-0016-S");

  script_name(english:"Amazon Linux 2 : ansible (ALASANSIBLE2-2023-008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ansible installed on the remote host is prior to 2.9.9-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2ANSIBLE2-2023-008 advisory.

    A flaw was found in Ansible Engine, all versions 2.7.x, 2.8.x and 2.9.x prior to 2.7.17, 2.8.9 and 2.9.6
    respectively, when using ansible_facts as a subkey of itself and promoting it to a variable when inject is
    enabled, overwriting the ansible_facts after the clean. An attacker could take advantage of this by
    altering the ansible_facts, such as ansible_hosts, users and any other key data which would lead into
    privilege escalation or code injection. (CVE-2020-10684)

    A flaw was found in Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x before
    2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and 3.5.5 and
    3.6.3 when using modules which decrypts vault files such as assemble, script, unarchive, win_copy, aws_s3
    or copy modules. The temporary directory is created in /tmp leaves the s ts unencrypted. On Operating
    Systems which /tmp is not a tmpfs but part of the root partition, the directory is only cleared on boot
    and the decryp emains when the host is switched off. The system will be vulnerable when the system is not
    running. So decrypted data must be cleared as soon as possible and the data which normally is encrypted
    ble. (CVE-2020-10685)

    An archive traversal flaw was found in all ansible-engine versions 2.9.x prior to 2.9.7, when running
    ansible-galaxy collection install. When extracting a collection .tar.gz file, the directory is created
    without sanitizing the filename. An attacker could take advantage to overwrite any file within the system.
    (CVE-2020-10691)

    A race condition flaw was found in Ansible Engine 2.7.17 and prior, 2.8.9 and prior, 2.9.6 and prior when
    running a playbook with an unprivileged become user. When Ansible needs to run a module with become user,
    the temporary directory is created in /var/tmp. This directory is created with umask 77 && mkdir -p
    <dir>; this operation does not fail if the directory already exists and is owned by another user. An
    attacker could take advantage to gain control of the become user as the target directory can be retrieved
    by iterating '/proc/<pid>/cmdline'. (CVE-2020-1733)

    A flaw was found in the Ansible Engine when the fetch module is used. An attacker could intercept the
    module, inject a new path, and then choose a new destination path on the controller node. All versions in
    2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable. (CVE-2020-1735)

    A flaw was found in Ansible Engine when using Ansible Vault for editing encrypted files. When a user
    executes ansible-vault edit, another user on the same computer can read the old and new secret, as it is
    created in a temporary file with mkstemp and the returned file descriptor is closed and the method
    write_data is called to write the existing secret in the file. This method will delete the file before
    recreating it insecurely. All versions in 2.7.x, 2.8.x and 2.9.x branches are believed to be vulnerable.
    (CVE-2020-1740)

    A flaw was found in the Ansible Engine affecting Ansible Engine versions 2.7.x before 2.7.17 and 2.8.x
    before 2.8.11 and 2.9.x before 2.9.7 as well as Ansible Tower before and including versions 3.4.5 and
    3.5.5 and 3.6.3 when the ldap_attr and ldap_entry community modules are used. The issue discloses the LDAP
    bind password to stdout or a log file if a playbook task is written using the bind_pw in the parameters
    field. The highest threat from this vulnerability is data confidentiality. (CVE-2020-1746)

    A security flaw was found in Ansible Engine, all Ansible 2.7.x versions prior to 2.7.17, all Ansible 2.8.x
    versions prior to 2.8.11 and all Ansible 2.9.x versions prior to 2.9.7, when managing kubernetes using the
    k8s module. Sensitive parameters such as passwords and tokens are passed to kubectl from the command line,
    not using an environment variable or an input configuration file. This will disclose passwords and tokens
    from process list and no_log directive from debug module would not have any effect making these secrets
    being disclosed on stdout and log files. (CVE-2020-1753)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASANSIBLE2-2023-008.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-10684.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-10685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-10691.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1733.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1740.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1746.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1753.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ansible' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1733");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10684");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ansible-2.9.9-1.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible2'},
    {'reference':'ansible-doc-2.9.9-1.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ansible2'}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / ansible-doc");
}
