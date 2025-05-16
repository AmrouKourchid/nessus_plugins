#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3820.
##

include('compat.inc');

if (description)
{
  script_id(200557);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id("CVE-2024-34064");
  script_xref(name:"RLSA", value:"2024:3820");

  script_name(english:"Rocky Linux 9 : fence-agents (RLSA-2024:3820)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:3820 advisory.

    * jinja2: accepts keys containing non-attribute characters (CVE-2024-34064)

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279476");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ibm-powervs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ibm-vpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-kubevirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-agents-zvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-cpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-cpg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-multicast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-multicast-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-serial-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-tcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fence-virtd-tcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ha-cloud-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ha-cloud-support-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'fence-agents-aliyun-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-all-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-all-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-all-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-amt-ws-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-apc-snmp-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-aws-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-azure-arm-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-bladecenter-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-brocade-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-mds-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-cisco-ucs-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-common-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-compute-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-drac5-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eaton-snmp-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-emerson-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-eps-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-gce-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-heuristics-ping-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-hpblade-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-powervs-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibm-vpc-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ibmblade-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ifmib-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-moonshot-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-mp-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo-ssh-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ilo2-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-intelmodular-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipdu-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-ipmilan-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-debuginfo-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-debuginfo-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kdump-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-debuginfo-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-debuginfo-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-kubevirt-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-lpar-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-mpath-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-openstack-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-redfish-4.10.0-62.el9_4.3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-redfish-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-redfish-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rhevm-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsa-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-rsb-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-sbd-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-scsi-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-virsh-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-rest-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-vmware-soap-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-wti-4.10.0-62.el9_4.3', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-agents-zvm-4.10.0-62.el9_4.3', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virt-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virt-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-cpg-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-cpg-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-libvirt-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-libvirt-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-multicast-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-multicast-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-serial-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-serial-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-tcp-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fence-virtd-tcp-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ha-cloud-support-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ha-cloud-support-debuginfo-4.10.0-62.el9_4.3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc');
}
