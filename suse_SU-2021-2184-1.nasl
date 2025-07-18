#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2184-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151125);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2020-26558",
    "CVE-2020-36385",
    "CVE-2020-36386",
    "CVE-2021-0129"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2184-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2021:2184-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:2184-1 advisory.

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - An issue was discovered in the Linux kernel before 5.8.1. net/bluetooth/hci_event.c has a slab out-of-
    bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf. (CVE-2020-36386)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0129");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/009097.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93bf5d0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_10-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-59.10.1.18.4.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-59.10.1.18.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-devel-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-devel-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-macros-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-macros-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-59.10.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-59.10.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-basesystem-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-source-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-source-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-syms-5.3.18-59.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'kernel-syms-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-development-tools-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-legacy-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-59.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-59_10-default-1-7.5.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-59.10.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
