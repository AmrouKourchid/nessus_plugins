#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:0894.
##

include('compat.inc');

if (description)
{
  script_id(235542);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2022-4899",
    "CVE-2023-21911",
    "CVE-2023-21919",
    "CVE-2023-21920",
    "CVE-2023-21929",
    "CVE-2023-21933",
    "CVE-2023-21935",
    "CVE-2023-21940",
    "CVE-2023-21945",
    "CVE-2023-21946",
    "CVE-2023-21947",
    "CVE-2023-21953",
    "CVE-2023-21955",
    "CVE-2023-21962",
    "CVE-2023-21966",
    "CVE-2023-21972",
    "CVE-2023-21976",
    "CVE-2023-21977",
    "CVE-2023-21980",
    "CVE-2023-21982",
    "CVE-2023-22005",
    "CVE-2023-22007",
    "CVE-2023-22008",
    "CVE-2023-22032",
    "CVE-2023-22033",
    "CVE-2023-22038",
    "CVE-2023-22046",
    "CVE-2023-22048",
    "CVE-2023-22053",
    "CVE-2023-22054",
    "CVE-2023-22056",
    "CVE-2023-22057",
    "CVE-2023-22058",
    "CVE-2023-22059",
    "CVE-2023-22064",
    "CVE-2023-22065",
    "CVE-2023-22066",
    "CVE-2023-22068",
    "CVE-2023-22070",
    "CVE-2023-22078",
    "CVE-2023-22079",
    "CVE-2023-22084",
    "CVE-2023-22092",
    "CVE-2023-22097",
    "CVE-2023-22103",
    "CVE-2023-22104",
    "CVE-2023-22110",
    "CVE-2023-22111",
    "CVE-2023-22112",
    "CVE-2023-22113",
    "CVE-2023-22114",
    "CVE-2023-22115",
    "CVE-2024-20960",
    "CVE-2024-20961",
    "CVE-2024-20962",
    "CVE-2024-20963",
    "CVE-2024-20964",
    "CVE-2024-20965",
    "CVE-2024-20966",
    "CVE-2024-20967",
    "CVE-2024-20968",
    "CVE-2024-20969",
    "CVE-2024-20970",
    "CVE-2024-20971",
    "CVE-2024-20972",
    "CVE-2024-20973",
    "CVE-2024-20974",
    "CVE-2024-20976",
    "CVE-2024-20977",
    "CVE-2024-20978",
    "CVE-2024-20981",
    "CVE-2024-20982",
    "CVE-2024-20983",
    "CVE-2024-20984",
    "CVE-2024-20985",
    "CVE-2024-20993",
    "CVE-2024-21049",
    "CVE-2024-21050",
    "CVE-2024-21051",
    "CVE-2024-21052",
    "CVE-2024-21053",
    "CVE-2024-21055",
    "CVE-2024-21056",
    "CVE-2024-21057",
    "CVE-2024-21061",
    "CVE-2024-21137",
    "CVE-2024-21200"
  );
  script_xref(name:"RLSA", value:"2024:0894");

  script_name(english:"RockyLinux 8 : mysql:8.0 (RLSA-2024:0894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:0894 advisory.

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2023) (CVE-2023-21911)

    * mysql: Server: DDL unspecified vulnerability (CPU Apr 2023) (CVE-2023-21919, CVE-2023-21929,
    CVE-2023-21933)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2023) (CVE-2023-21920, CVE-2023-21935,
    CVE-2023-21945, CVE-2023-21946, CVE-2023-21976, CVE-2023-21977, CVE-2023-21982)

    * mysql: Server: Components Services unspecified vulnerability (CPU Apr 2023) (CVE-2023-21940,
    CVE-2023-21947, CVE-2023-21962)

    * mysql: Server: Partition unspecified vulnerability (CPU Apr 2023) (CVE-2023-21953, CVE-2023-21955)

    * mysql: Server: JSON unspecified vulnerability (CPU Apr 2023) (CVE-2023-21966)

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2023) (CVE-2023-21972)

    * mysql: Client programs unspecified vulnerability (CPU Apr 2023) (CVE-2023-21980)

    * mysql: Server: Replication unspecified vulnerability (CPU Jul 2023) (CVE-2023-22005, CVE-2023-22007,
    CVE-2023-22057)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2023) (CVE-2023-22008)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2023) (CVE-2023-22032, CVE-2023-22059,
    CVE-2023-22064, CVE-2023-22065, CVE-2023-22070, CVE-2023-22078, CVE-2023-22079, CVE-2023-22092,
    CVE-2023-22103, CVE-2023-22110, CVE-2023-22112)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2023) (CVE-2023-22033)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2023) (CVE-2023-22046, CVE-2023-22054,
    CVE-2023-22056)

    * mysql: Client programs unspecified vulnerability (CPU Jul 2023) (CVE-2023-22053)

    * mysql: Server: DDL unspecified vulnerability (CPU Jul 2023) (CVE-2023-22058)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2023) (CVE-2023-22066, CVE-2023-22068, CVE-2023-22084,
    CVE-2023-22097, CVE-2023-22104, CVE-2023-22114)

    * mysql: Server: UDF unspecified vulnerability (CPU Oct 2023) (CVE-2023-22111)

    * mysql: Server: DML unspecified vulnerability (CPU Oct 2023) (CVE-2023-22115)

    * mysql: Server: RAPID unspecified vulnerability (CPU Jan 2024) (CVE-2024-20960)

    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2024) (CVE-2024-20963)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2024) (CVE-2024-20964)

    * mysql: Server: Replication unspecified vulnerability (CPU Jan 2024) (CVE-2024-20967)

    * mysql: Server: Options unspecified vulnerability (CPU Jan 2024) (CVE-2024-20968)

    * mysql: Server: DDL unspecified vulnerability (CPU Jan 2024) (CVE-2024-20969)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2024) (CVE-2024-20961, CVE-2024-20962,
    CVE-2024-20965, CVE-2024-20966, CVE-2024-20970, CVE-2024-20971, CVE-2024-20972, CVE-2024-20973,
    CVE-2024-20974, CVE-2024-20976, CVE-2024-20977, CVE-2024-20978, CVE-2024-20982)

    * mysql: Server: DDL unspecified vulnerability (CPU Jan 2024) (CVE-2024-20981)

    * mysql: Server: DML unspecified vulnerability (CPU Jan 2024) (CVE-2024-20983)

    * mysql: Server : Security : Firewall unspecified vulnerability (CPU Jan 2024) (CVE-2024-20984)

    * mysql: Server: UDF unspecified vulnerability (CPU Jan 2024) (CVE-2024-20985)

    * zstd: mysql: buffer overrun in util.c (CVE-2022-4899)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2023) (CVE-2023-22038)

    * mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2023) (CVE-2023-22048)

    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2023) (CVE-2023-22113)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:0894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2245034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2258794");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:mysql-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var appstreams = {
    'mysql:8.0': [
      {'reference':'mecab-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debuginfo-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debuginfo-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debuginfo-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debuginfo-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debugsource-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debugsource-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debugsource-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-debugsource-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-devel-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-devel-0.996-2.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-devel-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-devel-0.996-2.module+el8.10.0+1937+28fbbc83', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-common-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-common-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-debugsource-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-debugsource-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-devel-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-devel-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-devel-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-devel-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-errmsg-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-errmsg-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-libs-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-libs-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-libs-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-libs-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-server-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-server-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-server-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-server-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-test-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-test-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-test-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'mysql-test-debuginfo-8.0.36-1.module+el8.10.0+1676+9b4b6e24', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-debuginfo / mecab-debugsource / mecab-devel / etc');
}
