#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2020-2.0-0261. The text
# itself is copyright (C) VMware, Inc.

include('compat.inc');

if (description)
{
  script_id(138515);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/23");

  script_cve_id("CVE-2020-15358");
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"Photon OS 2.0: Sqlite PHSA-2020-2.0-0261");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the sqlite package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-2-261.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (_release !~ "^VMware Photon (?:Linux|OS) 2\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 2.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'sqlite-3.32.1-2.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'sqlite-devel-3.32.1-2.ph2')) flag++;
if (rpm_check(release:'PhotonOS-2.0', cpu:'x86_64', reference:'sqlite-libs-3.32.1-2.ph2')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sqlite');
}
