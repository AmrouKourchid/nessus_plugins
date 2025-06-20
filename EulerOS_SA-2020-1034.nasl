#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132627);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/01");

  script_cve_id(
    "CVE-2019-12523",
    "CVE-2019-12526",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679"
  );

  script_name(english:"EulerOS 2.0 SP8 : squid (EulerOS-SA-2020-1034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in Squid before 4.9. When
    handling a URN request, a corresponding HTTP request is
    made. This HTTP request doesn't go through the access
    checks that incoming HTTP requests go through. This
    causes all access checks to be bypassed and allows
    access to restricted HTTP servers, e.g., an attacker
    can connect to HTTP servers that only listen on
    localhost.(CVE-2019-12523)

  - An issue was discovered in Squid before 4.9. URN
    response handling in Squid suffers from a heap-based
    buffer overflow. When receiving data from a remote
    server in response to an URN request, Squid fails to
    ensure that the response can fit within the buffer.
    This leads to attacker controlled data overflowing in
    the heap.(CVE-2019-12526)

  - An issue was discovered in Squid 3.x and 4.x through
    4.8. Due to incorrect input validation, there is a
    heap-based buffer overflow that can result in Denial of
    Service to all clients using the proxy. Severity is
    high due to this vulnerability occurring before normal
    security checks any remote client that can reach the
    proxy port can trivially perform the attack via a
    crafted URI scheme.(CVE-2019-18676)

  - An issue was discovered in Squid 3.x and 4.x through
    4.8 when the append_domain setting is used (because the
    appended characters do not properly interact with
    hostname length restrictions). Due to incorrect message
    processing, it can inappropriately redirect traffic to
    origins it should not be delivered to.(CVE-2019-18677)

  - An issue was discovered in Squid 3.x and 4.x through
    4.8. It allows attackers to smuggle HTTP requests
    through frontend software to a Squid instance that
    splits the HTTP Request pipeline differently. The
    resulting Response messages corrupt caches (between a
    client and Squid) with attacker-controlled content at
    arbitrary URLs. Effects are isolated to software
    between the attacker client and Squid. There are no
    effects on Squid itself, nor on any upstream servers.
    The issue is related to a request header containing
    whitespace between a header name and a
    colon.(CVE-2019-18678)

  - An issue was discovered in Squid 2.x, 3.x, and 4.x
    through 4.8. Due to incorrect data management, it is
    vulnerable to information disclosure when processing
    HTTP Digest Authentication. Nonce tokens contain the
    raw byte value of a pointer that sits within heap
    memory allocation. This information reduces ASLR
    protections and may aid attackers isolating memory
    areas to target for remote code execution
    attacks.(CVE-2019-18679)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1034
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f64f59d");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["squid-4.2-2.h2.eulerosv2r8"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
