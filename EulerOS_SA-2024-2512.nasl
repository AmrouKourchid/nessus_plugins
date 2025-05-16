#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208349);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2024-5535");

  script_name(english:"EulerOS 2.0 SP12 : openssl (EulerOS-SA-2024-2512)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an empty supported client
    protocols buffer may cause a crash or memory contents to be sent to the peer. Impact summary: A buffer
    overread can have a range of potential consequences such as unexpected application beahviour or a crash.
    In particular this issue could result in up to 255 bytes of arbitrary private data from memory being sent
    to the peer leading to a loss of confidentiality. However, only applications that directly call the
    SSL_select_next_proto function with a 0 length list of supported client protocols are affected by this
    issue. This would normally never be a valid scenario and is typically not under attacker control but may
    occur by accident in the case of a configuration or programming error in the calling application. The
    OpenSSL API function SSL_select_next_proto is typically used by TLS applications that support ALPN
    (Application Layer Protocol Negotiation) or NPN (Next Protocol Negotiation). NPN is older, was never
    standardised and is deprecated in favour of ALPN. We believe that ALPN is significantly more widely
    deployed than NPN. The SSL_select_next_proto function accepts a list of protocols from the server and a
    list of protocols from the client and returns the first protocol that appears in the server list that also
    appears in the client list. In the case of no overlap between the two lists it returns the first item in
    the client list. In either case it will signal whether an overlap between the two lists was found. In the
    case where SSL_select_next_proto is called with a zero length client list it fails to notice this
    condition and returns the memory immediately following the client list pointer (and reports that there was
    no overlap in the lists). This function is typically called from a server side application callback for
    ALPN or a client side application callback for NPN. In the case of ALPN the list of protocols supplied by
    the client is guaranteed by libssl to never be zero in length. The list of server protocols comes from the
    application and should never normally be expected to be of zero length. In this case if the
    SSL_select_next_proto function has been called as expected (with the list supplied by the client passed in
    the client/client_len parameters), then the application will not be vulnerable to this issue. If the
    application has accidentally been configured with a zero length server list, and has accidentally passed
    that zero length server list in the client/client_len parameters, and has additionally failed to correctly
    handle a 'no overlap' response (which would normally result in a handshake failure in ALPN) then it will
    be vulnerable to this problem. In the case of NPN, the protocol permits the client to opportunistically
    select a protocol when there is no overlap. OpenSSL returns the first client protocol in the no overlap
    case in support of this. The list of client protocols comes from the application and should never normally
    be expected to be of zero length. However if the SSL_select_next_proto function is accidentally called
    with a client_len of 0 then an invalid memory pointer will be returned instead. If the application uses
    this output as the opportunistic protocol then the loss of confidentiality will occur. This issue has been
    assessed as Low severity because applications are most likely to be vulnerable if they are using NPN
    instead of ALPN - but NPN is not widely used. It also requires an application configuration or programming
    error. Finally, this issue would not typically be under attacker control making active exploitation
    unlikely. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue. Due to the low
    severity of this issue we are not issuing new releases of OpenSSL at this time. The fix will be included
    in the next releases when they become available.(CVE-2024-5535)

Tenable has extracted the preceding description block directly from the EulerOS openssl security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2512
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1dca830");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-perl-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "openssl-1.1.1m-15.h42.eulerosv2r12",
  "openssl-libs-1.1.1m-15.h42.eulerosv2r12",
  "openssl-perl-1.1.1m-15.h42.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
