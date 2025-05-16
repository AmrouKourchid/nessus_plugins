##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10014-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162400);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/10");

  script_cve_id(
    "CVE-2020-26266",
    "CVE-2020-26267",
    "CVE-2020-26268",
    "CVE-2020-26270",
    "CVE-2020-26271",
    "CVE-2021-37635",
    "CVE-2021-37636",
    "CVE-2021-37637",
    "CVE-2021-37638",
    "CVE-2021-37639",
    "CVE-2021-37640",
    "CVE-2021-37641",
    "CVE-2021-37642",
    "CVE-2021-37643",
    "CVE-2021-37644",
    "CVE-2021-37645",
    "CVE-2021-37646",
    "CVE-2021-37647",
    "CVE-2021-37648",
    "CVE-2021-37649",
    "CVE-2021-37650",
    "CVE-2021-37651",
    "CVE-2021-37652",
    "CVE-2021-37653",
    "CVE-2021-37654",
    "CVE-2021-37655",
    "CVE-2021-37656",
    "CVE-2021-37657",
    "CVE-2021-37658",
    "CVE-2021-37659",
    "CVE-2021-37660",
    "CVE-2021-37661",
    "CVE-2021-37662",
    "CVE-2021-37663",
    "CVE-2021-37664",
    "CVE-2021-37665",
    "CVE-2021-37666",
    "CVE-2021-37667",
    "CVE-2021-37668",
    "CVE-2021-37669",
    "CVE-2021-37670",
    "CVE-2021-37671",
    "CVE-2021-37672",
    "CVE-2021-37673",
    "CVE-2021-37674",
    "CVE-2021-37675",
    "CVE-2021-37676",
    "CVE-2021-37677",
    "CVE-2021-37678",
    "CVE-2021-37679",
    "CVE-2021-37680",
    "CVE-2021-37681",
    "CVE-2021-37682",
    "CVE-2021-37683",
    "CVE-2021-37684",
    "CVE-2021-37685",
    "CVE-2021-37686",
    "CVE-2021-37687",
    "CVE-2021-37688",
    "CVE-2021-37689",
    "CVE-2021-37690",
    "CVE-2021-37691",
    "CVE-2021-37692"
  );

  script_name(english:"openSUSE 15 Security Update : tensorflow2 (openSUSE-SU-2022:10014-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2022:10014-1 advisory.

    Update to TF2 2.6.0 which fixes multiple CVEs (boo#1189423).

    - Introduction of bazel6.3 and basel-skylib1.0.3 as build
      dependencies.
      The latter has been adapted to all a version in its package
      name (if %set_ver_suffix is set to 1). This allows multiple
      versions to exist for one product (not installed).
      NOTE: basel-skylib1.0.3 does not exist in oS:Factory:
      basel-skylib in oS:Factory - the base version - is 1.0.3.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189423");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U25ZU2T5T4LOLSIYIMGC5PLU4PQQMJE5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4d9e5f4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37692");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37690");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37678");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bazel-skylib1.0.3-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bazel3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiomp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiomp5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiomp5-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_cc2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtensorflow_framework2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_6_0-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_6_0-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_6_0-gnu-openmpi2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tensorflow2_2_6_0-gnu-openmpi2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'bazel-skylib1.0.3-source-1.0.3-bp153.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bazel3.7-3.7.2-bp153.4.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bazel3.7-3.7.2-bp153.4.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiomp5-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiomp5-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libiomp5-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_cc2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtensorflow_framework2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-devel-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-devel-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-2.6.0-bp153.2.3.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-devel-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-devel-2.6.0-bp153.2.3.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2-lite-devel-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-hpc-devel-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-hpc-devel-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-openmpi2-hpc-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-openmpi2-hpc-devel-2.6.0-bp153.2.3.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tensorflow2_2_6_0-gnu-openmpi2-hpc-devel-2.6.0-bp153.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bazel-skylib1.0.3-source / bazel3.7 / libiomp5 / libiomp5-gnu-hpc / etc');
}
