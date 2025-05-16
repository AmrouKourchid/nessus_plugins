#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202668);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/18");

  script_cve_id(
    "CVE-2023-45229",
    "CVE-2023-45230",
    "CVE-2023-45231",
    "CVE-2023-45232",
    "CVE-2023-45233",
    "CVE-2023-45234",
    "CVE-2023-45235",
    "CVE-2023-45236",
    "CVE-2023-45237"
  );

  script_name(english:"EulerOS Virtualization 2.10.1 : edk2 (EulerOS-SA-2024-2014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the edk2 package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

    EDK2's Network Package is susceptible to a buffer overflow vulnerability when handling Server ID option
    from a DHCPv6 proxy Advertise message. This vulnerability can be exploited by an attacker to gain
    unauthorized access and potentially lead to a loss of Confidentiality, Integrity and/or
    Availability.(CVE-2023-45235)

    EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. This vulnerability can
    be exploited by an attacker to gain unauthorized access and potentially lead to a loss of
    Confidentiality.(CVE-2023-45234)

    EDK2's Network Package is susceptible to an out-of-bounds read vulnerability when processing the IA_NA or
    IA_TA option in a DHCPv6 Advertise message. This vulnerability can be exploited by an attacker to gain
    unauthorized access and potentially lead to a loss of Confidentiality.(CVE-2023-45229)

    EDK2's Network Package is susceptible to a buffer overflow vulnerability via a long server ID option in
    DHCPv6 client. This vulnerability can be exploited by an attacker to gain unauthorized access and
    potentially lead to a loss of Confidentiality, Integrity and/or Availability.(CVE-2023-45230)

    EDK2's Network Package is susceptible to an infinite loop vulnerability when parsing unknown options in
    the Destination Options header of IPv6. This vulnerability can be exploited by an attacker to gain
    unauthorized access and potentially lead to a loss of Availability.(CVE-2023-45232)

    EDK2's Network Package is susceptible to an infinite lop vulnerability when parsing a PadN option in the
    Destination Options header of IPv6. This vulnerability can be exploited by an attacker to gain
    unauthorized  access and potentially lead to a loss of Availability.(CVE-2023-45233)

    EDK2's Network Package is susceptible to an out-of-bounds read vulnerability when processing Neighbor
    Discovery Redirect message. This vulnerability can be exploited by an attacker to gain unauthorized access
    and potentially lead to a loss of Confidentiality.(CVE-2023-45231)

    EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. This vulnerability can
    be exploited by an attacker to gain unauthorized  access and potentially lead to a loss of
    Confidentiality.(CVE-2023-45236)

    EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. This vulnerability can
    be exploited by an attacker to gain unauthorized  access and potentially lead to a loss of
    Confidentiality.(CVE-2023-45237)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization edk2 security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ff55782");
  script_set_attribute(attribute:"solution", value:
"Update the affected edk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.1");
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
if (uvp != "2.10.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "edk2-aarch64-202011-2.10.0.5.24"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk2");
}
