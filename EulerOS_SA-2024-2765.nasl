#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209783);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/27");

  script_cve_id("CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");

  script_name(english:"EulerOS Virtualization 2.12.0 : bind (EulerOS-SA-2024-2765)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

    Resolver caches and authoritative zone databases that hold significant numbers of RRs for the same
    hostname (of any RTYPE) can suffer from degraded performance as content is being added or updated, and
    also when handling client queries for this name.
    This issue affects BIND 9 versions 9.11.0 through 9.11.37, 9.16.0 through 9.16.50, 9.18.0 through 9.18.27,
    9.19.0 through 9.19.24, 9.11.4-S1 through 9.11.37-S1, 9.16.8-S1 through 9.16.50-S1, and 9.18.11-S1 through
    9.18.27-S1.(CVE-2024-1737)

    Client queries that trigger serving stale data and that also require lookups in local authoritative zone
    data may result in an assertion failure.This issue affects BIND 9 versions 9.16.13 through 9.16.50, 9.18.0
    through 9.18.27, 9.19.0 through 9.19.24, 9.11.33-S1 through 9.11.37-S1, 9.16.13-S1 through 9.16.50-S1, and
    9.18.11-S1 through 9.18.27-S1.(CVE-2024-4076)

    If a server hosts a zone containing a 'KEY' Resource Record, or a resolver DNSSEC-validates a 'KEY'
    Resource Record from a DNSSEC-signed domain in cache, a client can exhaust resolver CPU resources by
    sending a stream of SIG(0) signed requests.
    This issue affects BIND 9 versions 9.0.0 through 9.11.37, 9.16.0 through 9.16.50, 9.18.0 through 9.18.27,
    9.19.0 through 9.19.24, 9.9.3-S1 through 9.11.37-S1, 9.16.8-S1 through 9.16.49-S1, and 9.18.11-S1 through
    9.18.27-S1.(CVE-2024-1975)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization bind security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2765
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?928cfbbc");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-dnssec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.12.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.12.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bind-9.16.23-15.h12.eulerosv2r12",
  "bind-chroot-9.16.23-15.h12.eulerosv2r12",
  "bind-dnssec-doc-9.16.23-15.h12.eulerosv2r12",
  "bind-dnssec-utils-9.16.23-15.h12.eulerosv2r12",
  "bind-libs-9.16.23-15.h12.eulerosv2r12",
  "bind-license-9.16.23-15.h12.eulerosv2r12",
  "bind-pkcs11-9.16.23-15.h12.eulerosv2r12",
  "bind-pkcs11-libs-9.16.23-15.h12.eulerosv2r12",
  "bind-pkcs11-utils-9.16.23-15.h12.eulerosv2r12",
  "bind-utils-9.16.23-15.h12.eulerosv2r12",
  "python3-bind-9.16.23-15.h12.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
