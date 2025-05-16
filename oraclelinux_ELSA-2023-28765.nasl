#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-28765.
##

include('compat.inc');

if (description)
{
  script_id(181324);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2023-4039");

  script_name(english:"Oracle Linux 8 / 9 : cross-gcc (ELSA-2023-28765)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-28765 advisory.

    - CVE-2023-4039 mitigation.
      Orabug 35752028.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-28765.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::developer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cross-gcc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-arc-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-arm-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-avr32-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-bfin-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-bpf-unknown-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-arc-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-arm-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-avr32-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-bfin-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-bpf-unknown-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-c6x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-frv-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-h8300-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-hppa64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-ia64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-microblaze-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-mips64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-mn10300-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-nios2-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-openrisc-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-powerpc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-powerpc64le-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-ppc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-ppc64le-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-riscv64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-sparc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-tile-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-x86_64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++-xtensa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c6x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-frv-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-h8300-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-hppa64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-ia64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-microblaze-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-mips64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-mn10300-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-nios2-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-openrisc-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-powerpc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-powerpc64le-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-ppc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-ppc64le-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-riscv64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-sparc64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-tile-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-x86_64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-xtensa-linux-gnu");
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
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cross-gcc-common-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-aarch64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-alpha-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arm-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-avr32-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bfin-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bpf-unknown-none-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-aarch64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-alpha-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arm-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-avr32-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bfin-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bpf-unknown-none-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-c6x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-frv-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-h8300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ia64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-m68k-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-microblaze-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mips64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mn10300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-nios2-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-openrisc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-riscv64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-s390x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-sparc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-tile-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-x86_64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-xtensa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c6x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-frv-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-h8300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ia64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-m68k-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-microblaze-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mips64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mn10300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-nios2-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-openrisc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-riscv64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-s390x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-sparc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-tile-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-x86_64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-xtensa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-aarch64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-alpha-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arm-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-avr32-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bfin-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bpf-unknown-none-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-aarch64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-alpha-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arm-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-avr32-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bfin-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bpf-unknown-none-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-c6x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-frv-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-h8300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ia64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-m68k-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-microblaze-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mips64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mn10300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-nios2-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-openrisc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-riscv64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-s390x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-sparc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-tile-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-x86_64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-xtensa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c6x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-frv-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-h8300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ia64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-m68k-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-microblaze-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mips64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mn10300-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-nios2-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-openrisc-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64le-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-riscv64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-s390x-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-sparc64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-tile-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-x86_64-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-xtensa-linux-gnu-12.1.1-2.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-gcc-common-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-aarch64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-alpha-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arm-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-avr32-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bfin-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bpf-unknown-none-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-aarch64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-alpha-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arm-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-avr32-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bfin-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bpf-unknown-none-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-c6x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-frv-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-h8300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ia64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-m68k-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-microblaze-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mips64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mn10300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-nios2-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-openrisc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-riscv64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-s390x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-sparc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-tile-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-x86_64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-xtensa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c6x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-frv-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-h8300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ia64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-m68k-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-microblaze-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mips64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mn10300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-nios2-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-openrisc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-riscv64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-s390x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-sparc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-tile-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-x86_64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-xtensa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-aarch64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-alpha-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-arm-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-avr32-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bfin-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-bpf-unknown-none-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-aarch64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-alpha-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-arm-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-avr32-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bfin-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-bpf-unknown-none-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-c6x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-frv-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-h8300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-hppa64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ia64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-m68k-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-microblaze-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mips64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-mn10300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-nios2-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-openrisc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-powerpc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-ppc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-riscv64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-s390x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-sparc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-tile-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-x86_64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-xtensa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c6x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-frv-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-h8300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-hppa64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ia64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-m68k-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-microblaze-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mips64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-mn10300-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-nios2-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-openrisc-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-powerpc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-ppc64le-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-riscv64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-s390x-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-sparc64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-tile-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-x86_64-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-xtensa-linux-gnu-12.1.1-2.0.4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cross-gcc-common / gcc-aarch64-linux-gnu / gcc-alpha-linux-gnu / etc');
}
