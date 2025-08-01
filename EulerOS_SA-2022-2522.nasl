#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165907);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/10");

  script_cve_id("CVE-2021-41495", "CVE-2021-41496");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : numpy (EulerOS-SA-2022-2522)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the numpy packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - ** DISPUTED ** Null Pointer Dereference vulnerability exists in numpy.sort in NumPy < and 1.19 in the
    PyArray_DescrNew function due to missing return-value validation, which allows attackers to conduct DoS
    attacks by repetitively creating sort arrays. NOTE: While correct that validation is missing, an error can
    only occur due to an exhaustion of memory. If the user can exhaust memory, they are already privileged.
    Further, it should be practically impossible to construct an attack which can target the memory exhaustion
    to occur at exactly this place. (CVE-2021-41495)

  - ** DISPUTED ** Buffer overflow in the array_from_pyobj function of fortranobject.c in NumPy < 1.19, which
    allows attackers to conduct a Denial of Service attacks by carefully constructing an array with negative
    values. NOTE: The vendor does not agree this is a vulnerability; the negative dimensions can only be
    created by an already privileged user (or internally). (CVE-2021-41496)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98d550c2");
  script_set_attribute(attribute:"solution", value:
"Update the affected numpy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41495");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41496");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "numpy-1.7.1-13.h4.eulerosv2r7",
  "numpy-f2py-1.7.1-13.h4.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "numpy");
}
