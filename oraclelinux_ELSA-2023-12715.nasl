#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12715.
##

include('compat.inc');

if (description)
{
  script_id(179853);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2023-20569");

  script_name(english:"Oracle Linux 9 : linux-firmware (ELSA-2023-12715)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-12715 advisory.

    [20230516-999.25.git6c9e0ed5.el9]
    - Add missing amd-ucode/ files to nano and core rpm (Orabug: 35642190)
    - Add posttrans scriptlet to reload microcode on AMD (Orabug: 35636951)
    - Recreate initramfs for AMD systems (Orabug: 35636951)

    [20230516-999.24.git6c9e0ed5.el7]
    - 8a07fa49 linux-firmware: Update AMD fam19h cpu microcode (Orabug: 35659485)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12715.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:2:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:iwlax2xx-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libertas-sd8686-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libertas-sd8787-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libertas-usb8388-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libertas-usb8388-olpc-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:linux-firmware-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:linux-firmware-whence");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:liquidio-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netronome-firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('aarch64' >!< cpu) audit(AUDIT_ARCH_NOT, 'aarch64', cpu);

var pkgs = [
    {'reference':'iwl100-firmware-39.31.5.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl1000-firmware-39.31.5.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl105-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl135-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl2000-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl2030-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl3160-firmware-25.30.13.0-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl3945-firmware-15.32.2.9-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl4965-firmware-228.61.2.24-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl5000-firmware-8.83.5.1_1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl5150-firmware-8.24.2.2-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl6000-firmware-9.221.4.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl6000g2a-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl6000g2b-firmware-18.168.6.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl6050-firmware-41.28.5.1-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwl7260-firmware-25.30.13.0-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'iwlax2xx-firmware-20230516-999.25.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'libertas-sd8686-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'libertas-sd8787-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'libertas-usb8388-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'libertas-usb8388-olpc-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'linux-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'linux-firmware-core-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'linux-firmware-whence-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'liquidio-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'},
    {'reference':'netronome-firmware-20230516-999.25.git6c9e0ed5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'999'}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc');
}
