##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162446);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/19");

  script_cve_id("CVE-2021-28544", "CVE-2022-24070");

  script_name(english:"EulerOS 2.0 SP8 : subversion (EulerOS-SA-2022-1952)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the subversion packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - Apache Subversion SVN authz protected copyfrom paths regression Subversion servers reveal 'copyfrom' paths
    that should be hidden according to configured path-based authorization (authz) rules. When a node has been
    copied from a protected location, users with access to the copy can see the 'copyfrom' path of the
    original. This also reveals the fact that the node was copied. Only the 'copyfrom' path is revealed; not
    its contents. Both httpd and svnserve servers are vulnerable. (CVE-2021-28544)

  - Subversion's mod_dav_svn is vulnerable to memory corruption. While looking up path-based authorization
    rules, mod_dav_svn servers may attempt to use memory which has already been freed. Affected Subversion
    mod_dav_svn servers 1.10.0 through 1.14.1 (inclusive). Servers that do not use mod_dav_svn are not
    affected. (CVE-2022-24070)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1952
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?780fe5eb");
  script_set_attribute(attribute:"solution", value:
"Update the affected subversion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "mod_dav_svn-1.10.2-1.h6.eulerosv2r8",
  "subversion-1.10.2-1.h6.eulerosv2r8",
  "subversion-libs-1.10.2-1.h6.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
