#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3215-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153643);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2016-6153",
    "CVE-2017-2518",
    "CVE-2017-10989",
    "CVE-2018-8740",
    "CVE-2018-20346",
    "CVE-2019-8457",
    "CVE-2019-16168",
    "CVE-2019-19244",
    "CVE-2019-19317",
    "CVE-2019-19603",
    "CVE-2019-19645",
    "CVE-2019-19646",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19924",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2019-19959",
    "CVE-2019-20218",
    "CVE-2020-9327",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-15358"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3215-1");
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : sqlite3 (SUSE-SU-2021:3215-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 / SLES_SAP12 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2021:3215-1 advisory.

  - SQLite before 3.8.9 does not properly implement the dequoting of collation-sequence names, which allows
    context-dependent attackers to cause a denial of service (uninitialized memory access and application
    crash) or possibly have unspecified other impact via a crafted COLLATE clause, as demonstrated by
    COLLATE at the end of a SELECT statement. (CVE-2015-3414)

  - The sqlite3VdbeExec function in vdbe.c in SQLite before 3.8.9 does not properly implement comparison
    operators, which allows context-dependent attackers to cause a denial of service (invalid free operation)
    or possibly have unspecified other impact via a crafted CHECK clause, as demonstrated by CHECK(0&O>O) in a
    CREATE TABLE statement. (CVE-2015-3415)

  - os_unix.c in SQLite before 3.13.0 improperly implements the temporary directory search algorithm, which
    might allow local users to obtain sensitive information, cause a denial of service (application crash), or
    have unspecified other impact by leveraging use of the current working directory for temporary files.
    (CVE-2016-6153)

  - The getNodeSize function in ext/rtree/rtree.c in SQLite through 3.19.3, as used in GDAL and other
    products, mishandles undersized RTree blobs in a crafted database, leading to a heap-based buffer over-
    read or possibly unspecified other impact. (CVE-2017-10989)

  - An issue was discovered in certain Apple products. iOS before 10.3.2 is affected. macOS before 10.12.5 is
    affected. tvOS before 10.2.1 is affected. watchOS before 3.2.2 is affected. The issue involves the
    SQLite component. It allows remote attackers to execute arbitrary code or cause a denial of service
    (buffer overflow and application crash) via a crafted SQL statement. (CVE-2017-2518)

  - SQLite before 3.25.3, when the FTS3 extension is enabled, encounters an integer overflow (and resultant
    buffer overflow) for FTS3 queries that occur after crafted changes to FTS3 shadow tables, allowing remote
    attackers to execute arbitrary code by leveraging the ability to run arbitrary SQL statements (such as in
    certain WebSQL use cases), aka Magellan. (CVE-2018-20346)

  - In SQLite through 3.22.0, databases whose schema is corrupted using a CREATE TABLE AS statement could
    cause a NULL pointer dereference, related to build.c and prepare.c. (CVE-2018-8740)

  - In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application
    because of missing validation of a sqlite_stat1 sz field, aka a severe division by zero in the query
    planner. (CVE-2019-16168)

  - sqlite3Select in select.c in SQLite 3.30.1 allows a crash if a sub-select uses both DISTINCT and window
    functions, and also has certain ORDER BY usage. (CVE-2019-19244)

  - lookupName in resolve.c in SQLite 3.30.1 omits bits from the colUsed bitmask in the case of a generated
    column, which allows attackers to cause a denial of service or possibly have unspecified other impact.
    (CVE-2019-19317)

  - SQLite 3.30.1 mishandles certain SELECT statements with a nonexistent VIEW, leading to an application
    crash. (CVE-2019-19603)

  - alter.c in SQLite through 3.30.1 allows attackers to trigger infinite recursion via certain types of self-
    referential views in conjunction with ALTER TABLE statements. (CVE-2019-19645)

  - pragma.c in SQLite through 3.30.1 mishandles NOT NULL in an integrity_check PRAGMA command in certain
    cases of generated columns. (CVE-2019-19646)

  - exprListAppendList in window.c in SQLite 3.30.1 allows attackers to trigger an invalid pointer dereference
    because constant integer values in ORDER BY clauses of window definitions are mishandled. (CVE-2019-19880)

  - flattenSubquery in select.c in SQLite 3.30.1 mishandles certain uses of SELECT DISTINCT involving a LEFT
    JOIN in which the right-hand side is a view. This can cause a NULL pointer dereference (or incorrect
    results). (CVE-2019-19923)

  - SQLite 3.30.1 mishandles certain parser-tree rewriting, related to expr.c, vdbeaux.c, and window.c. This
    is caused by incorrect sqlite3WindowRewrite() error handling. (CVE-2019-19924)

  - zipfileUpdate in ext/misc/zipfile.c in SQLite 3.30.1 mishandles a NULL pathname during an update of a ZIP
    archive. (CVE-2019-19925)

  - multiSelect in select.c in SQLite 3.30.1 mishandles certain errors during parsing, as demonstrated by
    errors from sqlite3WindowRewrite() calls. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2019-19880. (CVE-2019-19926)

  - ext/misc/zipfile.c in SQLite 3.30.1 mishandles certain uses of INSERT INTO in situations involving
    embedded '\0' characters in filenames, leading to a memory-management error that can be detected by (for
    example) valgrind. (CVE-2019-19959)

  - selectExpander in select.c in SQLite 3.30.1 proceeds with WITH stack unwinding even after a parsing error.
    (CVE-2019-20218)

  - SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable to heap out-of-bound read in the rtreenode()
    function when handling invalid rtree tables. (CVE-2019-8457)

  - SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in printf.c. (CVE-2020-13434)

  - SQLite through 3.32.0 has a segmentation fault in sqlite3ExprCodeTarget in expr.c. (CVE-2020-13435)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

  - In SQLite before 3.32.3, select.c mishandles query-flattener optimization, leading to a multiSelectOrderBy
    heap overflow because of misuse of transitive properties for constant propagation. (CVE-2020-15358)

  - In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL pointer dereference and
    segmentation fault because of generated column optimizations. (CVE-2020-9327)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/928700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/928701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3415");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-10989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-2518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19317");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9327");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009509.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b948800c");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsqlite3-0, libsqlite3-0-32bit, sqlite3 and / or sqlite3-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsqlite3-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sqlite3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.2']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.2']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.2']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.2']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'sqlite3-devel-3.36.0-9.18.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsqlite3-0-3.36.0-9.18.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libsqlite3-0-32bit-3.36.0-9.18.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'sqlite3-3.36.0-9.18.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsqlite3-0 / libsqlite3-0-32bit / sqlite3 / sqlite3-devel');
}
