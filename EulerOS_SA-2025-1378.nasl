#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234155);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2024-12085",
    "CVE-2024-12086",
    "CVE-2024-12087",
    "CVE-2024-12088",
    "CVE-2024-12747"
  );

  script_name(english:"EulerOS 2.0 SP11 : rsync (EulerOS-SA-2025-1378)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the rsync package installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    A flaw was found in rsync. When using the `--safe-links` option, the rsync client fails to properly verify
    if a symbolic link destination sent from the server contains another symbolic link within it. This results
    in a path traversal vulnerability, which may lead to arbitrary file write outside the desired
    directory.(CVE-2024-12088)

    A path traversal vulnerability exists in rsync. It stems from behavior enabled by the `--inc-recursive`
    option, a default-enabled option for many client options and can be enabled by the server even if not
    explicitly enabled by the client. When using the `--inc-recursive` option, a lack of proper symlink
    verification coupled with deduplication checks occurring on a per-file-list basis could allow a server to
    write files outside of the client's intended destination directory. A malicious server could write
    malicious files to arbitrary locations named after valid directories/paths on the client.(CVE-2024-12087)

    A flaw was found in rsync. It could allow a server to enumerate the contents of an arbitrary file from the
    client's machine. This issue occurs when files are being copied from a client to a server. During this
    process, the rsync server will send checksums of local data to the client to compare with in order to
    determine what data needs to be sent to the server. By sending specially constructed checksum values for
    arbitrary files, an attacker may be able to reconstruct the data of those files byte-by-byte based on the
    responses from the client.(CVE-2024-12086)

    A flaw was found in rsync which could be triggered when rsync compares file checksums. This flaw allows an
    attacker to manipulate the checksum length (s2length) to cause a comparison between a checksum and
    uninitialized memory and leak one byte of uninitialized stack data at a time.(CVE-2024-12085)

    A flaw was found in rsync. This vulnerability arises from a race condition during rsync's handling of
    symbolic links. Rsync's default behavior when encountering symbolic links is to skip them. If an attacker
    replaced a regular file with a symbolic link at the right time, it was possible to bypass the default
    behavior and traverse symbolic links. Depending on the privileges of the rsync process, an attacker could
    leak sensitive information, potentially leading to privilege escalation.(CVE-2024-12747)

Tenable has extracted the preceding description block directly from the EulerOS rsync security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1378
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aef96560");
  script_set_attribute(attribute:"solution", value:
"Update the affected rsync packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12087");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-12085");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "rsync-3.2.3-2.h9.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync");
}
