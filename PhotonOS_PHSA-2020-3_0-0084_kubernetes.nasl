#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2020-3.0-0084. The text
# itself is copyright (C) VMware, Inc.

include('compat.inc');

if (description)
{
  script_id(136099);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2019-11250", "CVE-2019-11251", "CVE-2020-8552");

  script_name(english:"Photon OS 3.0: Kubernetes PHSA-2020-3.0-0084");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the kubernetes package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-3.0-84.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11251");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11250");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item('Host/PhotonOS/release');
if (isnull(_release) || _release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (_release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_exists(rpm:'kubernetes-1.12', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-1.12.10-3.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-1.14', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-1.14.10-1.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-debuginfo-1.12.10-3.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-kubeadm-1.12', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-kubeadm-1.12.10-3.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-kubeadm-1.14', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-kubeadm-1.14.10-1.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-kubectl-extras-1.12', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-kubectl-extras-1.12.10-3.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-kubectl-extras-1.14', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-kubectl-extras-1.14.10-1.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-pause-1.12', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-pause-1.12.10-3.ph3')) flag++;
if (rpm_exists(rpm:'kubernetes-pause-1.14', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'kubernetes-pause-1.14.10-1.ph3')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kubernetes');
}
