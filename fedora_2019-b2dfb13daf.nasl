#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-b2dfb13daf.
#

include('compat.inc');

if (description)
{
  script_id(126532);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id(
    "CVE-2019-10161",
    "CVE-2019-10166",
    "CVE-2019-10167",
    "CVE-2019-10168",
    "CVE-2019-3886"
  );
  script_xref(name:"FEDORA", value:"2019-b2dfb13daf");

  script_name(english:"Fedora 30 : libvirt (2019-b2dfb13daf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"- CVE-2019-10161: arbitrary file read/exec via
    virDomainSaveImageGetXMLDesc API (bz #1722463, bz
    #1720115)

  - CVE-2019-10166: virDomainManagedSaveDefineXML API
    exposed to readonly clients (bz #1722462, bz #1720114)

  - CVE-2019-10167: arbitrary command execution via
    virConnectGetDomainCapabilities API (bz #1722464, bz
    #1720117)

  - CVE-2019-10168: arbitrary command execution via
    virConnectBaselineHypervisorCPU and
    virConnectCompareHypervisorCPU APIs (bz #1722466, bz
    #1720118)

  - CVE-2019-3886: virsh domhostname command discloses guest
    hostname in readonly mode [fedora-rawhide

  - Cannot start VM with a CBR 2.0 TPM device (bz #1712556)

  - libvirtd does not update VM .xml configurations after
    virsh snapshot/blockcommit (bz #1722348)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-b2dfb13daf");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10161");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10168");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"libvirt-5.1.0-9.fc30")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
