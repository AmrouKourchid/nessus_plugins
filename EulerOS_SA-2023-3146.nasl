#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188764);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2023-2454", "CVE-2023-2455", "CVE-2023-39417");
  script_xref(name:"IAVB", value:"2023-B-0034-S");
  script_xref(name:"IAVB", value:"2023-B-0060-S");

  script_name(english:"EulerOS 2.0 SP8 : postgresql (EulerOS-SA-2023-3146)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the postgresql packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - schema_element defeats protective search_path changes; It was found that certain database calls in
    PostgreSQL could permit an authed attacker with elevated database-level privileges to execute arbitrary
    code. (CVE-2023-2454)

  - Row security policies disregard user ID changes after inlining; PostgreSQL could permit incorrect policies
    to be applied in certain cases where role-specific policies are used and a given query is planned under
    one role and then executed under other roles. This scenario can happen under security definer functions or
    when a common user and query is planned initially and then re-used across multiple SET ROLEs. Applying an
    incorrect policy may permit a user to complete otherwise-forbidden reads and modifications. This affects
    only databases that have used CREATE POLICY to define a row security policy. (CVE-2023-2455)

  - IN THE EXTENSION SCRIPT, a SQL Injection vulnerability was found in PostgreSQL if it uses @extowner@,
    @extschema@, or @extschema:...@ inside a quoting construct (dollar quoting, '', or ''). If an
    administrator has installed files of a vulnerable, trusted, non-bundled extension, an attacker with
    database-level CREATE privilege can execute arbitrary code as the bootstrap superuser. (CVE-2023-39417)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3146
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6aefff1");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "postgresql-10.5-3.h20.eulerosv2r8",
  "postgresql-contrib-10.5-3.h20.eulerosv2r8",
  "postgresql-devel-10.5-3.h20.eulerosv2r8",
  "postgresql-docs-10.5-3.h20.eulerosv2r8",
  "postgresql-libs-10.5-3.h20.eulerosv2r8",
  "postgresql-plperl-10.5-3.h20.eulerosv2r8",
  "postgresql-plpython-10.5-3.h20.eulerosv2r8",
  "postgresql-pltcl-10.5-3.h20.eulerosv2r8",
  "postgresql-server-10.5-3.h20.eulerosv2r8",
  "postgresql-test-10.5-3.h20.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql");
}
