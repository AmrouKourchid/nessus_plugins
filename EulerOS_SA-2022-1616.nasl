##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160587);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/31");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996");

  script_name(english:"EulerOS Virtualization 2.9.1 : util-linux (EulerOS-SA-2022-1616)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the util-linux packages installed, the EulerOS Virtualization installation on the remote
host is affected by the following vulnerabilities :

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows a local user on a vulnerable system to unmount other
    users' filesystems that are either world-writable themselves (like /tmp) or mounted in a world-writable
    directory. An attacker may use this flaw to cause a denial of service to applications that use the
    affected filesystems. (CVE-2021-3996)

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows an unprivileged local attacker to unmount FUSE
    filesystems that belong to certain other users who have a UID that is a prefix of the UID of the attacker
    in its string form. An attacker may use this flaw to cause a denial of service to applications that use
    the affected filesystems. (CVE-2021-3995)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1616
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfe8cf37");
  script_set_attribute(attribute:"solution", value:
"Update the affected util-linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libfdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmartcols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "libblkid-2.35.1-1.h24.eulerosv2r9",
  "libfdisk-2.35.1-1.h24.eulerosv2r9",
  "libmount-2.35.1-1.h24.eulerosv2r9",
  "libsmartcols-2.35.1-1.h24.eulerosv2r9",
  "libuuid-2.35.1-1.h24.eulerosv2r9",
  "util-linux-2.35.1-1.h24.eulerosv2r9",
  "util-linux-user-2.35.1-1.h24.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
