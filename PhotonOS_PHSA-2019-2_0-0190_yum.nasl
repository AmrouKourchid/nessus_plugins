#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2019-2.0-0190. The text
# itself is copyright (C) VMware, Inc.

include('compat.inc');

if (description)
{
  script_id(132535);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/22");

  script_cve_id("CVE-2013-1910");
  script_bugtraq_id(58533);

  script_name(english:"Photon OS 2.0: Yum PHSA-2019-2.0-0190");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the yum package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-2-190.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1910");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:yum");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item('Host/PhotonOS/release');
if (isnull(_release) || _release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (_release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 2.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-2.0', reference:'yum-3.4.3-9.ph2')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'yum');
}
