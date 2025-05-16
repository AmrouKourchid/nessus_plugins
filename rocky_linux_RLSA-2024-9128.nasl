#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:9128.
##

include('compat.inc');

if (description)
{
  script_id(232946);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2024-8235");
  script_xref(name:"RLSA", value:"2024:9128");

  script_name(english:"RockyLinux 9 : libvirt (RLSA-2024:9128)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:9128 advisory.

    * libvirt: Crash of virtinterfaced via virConnectListInterfaces() (CVE-2024-8235)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:9128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2308680");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-client-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-lock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-log-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-plugin-lockd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-plugin-lockd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-plugin-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-plugin-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-daemon-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-ssh-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libvirt-ssh-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'libvirt-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-qemu-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-qemu-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-client-qemu-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-common-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-network-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-network-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-network-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-network-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-nwfilter-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-nwfilter-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-nwfilter-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-config-nwfilter-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-interface-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-network-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nodedev-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-nwfilter-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-qemu-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-secret-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-core-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-disk-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-iscsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-logical-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-mpath-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-rbd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-driver-storage-scsi-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-kvm-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-kvm-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-kvm-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-lock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-log-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-lockd-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-plugin-sanlock-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-daemon-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debugsource-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debugsource-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debugsource-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-debugsource-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-devel-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-devel-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-devel-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-devel-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-docs-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-docs-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-docs-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-docs-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-libs-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-debuginfo-10.5.0-7.4.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-nss-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libvirt-ssh-proxy-debuginfo-10.5.0-7.4.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-client / libvirt-client-debuginfo / etc');
}
