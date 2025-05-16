#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6891-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202187);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2018-1060",
    "CVE-2018-1061",
    "CVE-2018-14647",
    "CVE-2018-20406",
    "CVE-2018-20852",
    "CVE-2019-5010",
    "CVE-2019-9636",
    "CVE-2019-9674",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948",
    "CVE-2019-10160",
    "CVE-2019-16056",
    "CVE-2019-16935",
    "CVE-2019-17514",
    "CVE-2019-18348",
    "CVE-2019-20907",
    "CVE-2020-8492",
    "CVE-2020-14422",
    "CVE-2020-26116",
    "CVE-2020-27619",
    "CVE-2021-3177",
    "CVE-2021-3426",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2021-29921",
    "CVE-2022-0391",
    "CVE-2022-42919",
    "CVE-2022-45061",
    "CVE-2022-48560",
    "CVE-2022-48564",
    "CVE-2022-48565",
    "CVE-2022-48566",
    "CVE-2023-6507",
    "CVE-2023-6597",
    "CVE-2023-24329",
    "CVE-2023-40217",
    "CVE-2023-41105",
    "CVE-2024-0450"
  );
  script_xref(name:"USN", value:"6891-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 : Python vulnerabilities (USN-6891-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6891-1 advisory.

    It was discovered that Python incorrectly handled certain inputs. An attacker could possibly use this
    issue to execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
    (CVE-2015-20107)

    It was discovered that Python incorrectly used regular expressions vulnerable to catastrophic
    backtracking. A remote attacker could possibly use this issue to cause a denial of service. This issue
    only affected Ubuntu 14.04 LTS. (CVE-2018-1060, CVE-2018-1061)

    It was discovered that Python failed to initialize Expats hash salt. A remote attacker could possibly
    use this issue to cause hash collisions, leading to a denial of service. This issue only affected Ubuntu
    14.04 LTS. (CVE-2018-14647)

    It was discovered that Python incorrectly handled certain pickle files. An attacker could possibly use
    this issue to consume memory, leading to a denial of service. This issue only affected Ubuntu 14.04 LTS.
    (CVE-2018-20406)

    It was discovered that Python incorrectly validated the domain when handling cookies. An attacker could
    possibly trick Python into sending cookies to the wrong domain. This issue only affected Ubuntu 14.04 LTS.
    (CVE-2018-20852)

    Jonathan Birch and Panayiotis Panayiotou discovered that Python incorrectly handled Unicode encoding
    during NFKC normalization. An attacker could possibly use this issue to obtain sensitive information. This
    issue only affected Ubuntu 14.04 LTS. (CVE-2019-9636, CVE-2019-10160)

    It was discovered that Python incorrectly parsed certain email addresses. A remote attacker could possibly
    use this issue to trick Python applications into accepting email addresses that should be denied. This
    issue only affected Ubuntu 14.04 LTS. (CVE-2019-16056)

    It was discovered that the Python documentation XML-RPC server incorrectly handled certain fields. A
    remote attacker could use this issue to execute a cross-site scripting (XSS) attack. This issue only
    affected Ubuntu 14.04 LTS. (CVE-2019-16935)

    It was discovered that Python documentation had a misleading information. A security issue could be
    possibly caused by wrong assumptions of this information. This issue only affected Ubuntu 14.04 LTS and
    Ubuntu 18.04 LTS. (CVE-2019-17514)

    It was discovered that Python incorrectly stripped certain characters from requests. A remote attacker
    could use this issue to perform CRLF injection. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04
    LTS. (CVE-2019-18348)

    It was discovered that Python incorrectly handled certain TAR archives. An attacker could possibly use
    this issue to cause a denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
    (CVE-2019-20907)

    Colin Read and Nicolas Edet discovered that Python incorrectly handled parsing certain X509 certificates.
    An attacker could possibly use this issue to cause Python to crash, resulting in a denial of service. This
    issue only affected Ubuntu 14.04 LTS. (CVE-2019-5010)

    It was discovered that incorrectly handled certain ZIP files. An attacker could possibly use this issue to
    cause a denial of service. This issue only affected Ubuntu 14.04 LTS. (CVE-2019-9674)

    It was discovered that Python incorrectly handled certain urls. A remote attacker could possibly use this
    issue to perform CRLF injection attacks. This issue only affected Ubuntu 14.04 LTS. (CVE-2019-9740,
    CVE-2019-9947)

    Sihoon Lee discovered that Python incorrectly handled the local_file: scheme. A remote attacker could
    possibly use this issue to bypass blocklist meschanisms. This issue only affected Ubuntu 14.04 LTS.
    (CVE-2019-9948)

    It was discovered that Python incorrectly handled certain IP values. An attacker could possibly use this
    issue to cause a denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
    (CVE-2020-14422)

    It was discovered that Python incorrectly handled certain character sequences. A remote attacker could
    possibly use this issue to perform CRLF injection. This issue only affected Ubuntu 14.04 LTS and Ubuntu
    18.04 LTS. (CVE-2020-26116)

    It was discovered that Python incorrectly handled certain inputs. An attacker could possibly use this
    issue to execute arbitrary code or cause a denial of service. This issue only affected Ubuntu 14.04 LTS.
    (CVE-2020-27619, CVE-2021-3177)

    It was discovered that Python incorrectly handled certain HTTP requests. An attacker could possibly use
    this issue to cause a denial of service. This issue only affected Ubuntu 14.04 LTS. (CVE-2020-8492)

    It was discovered that the Python stdlib ipaddress API incorrectly handled octal strings. A remote
    attacker could possibly use this issue to perform a wide variety of attacks, including bypassing certain
    access restrictions. This issue only affected Ubuntu 18.04 LTS. (CVE-2021-29921)

    David Schwrer discovered that Python incorrectly handled certain inputs. An attacker could possibly use
    this issue to expose sensitive information. This issue only affected Ubuntu 18.04 LTS. (CVE-2021-3426)

    It was discovered that Python incorrectly handled certain RFCs. An attacker could possibly use this issue
    to cause a denial of service. This issue only affected Ubuntu 14.04 LTS. (CVE-2021-3733)

    It was discovered that Python incorrectly handled certain server responses. An attacker could possibly use
    this issue to cause a denial of service. This issue only affected Ubuntu 14.04 LTS. (CVE-2021-3737)

    It was discovered that Python incorrectly handled certain FTP requests. An attacker could possibly use
    this issue to expose sensitive information. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04
    LTS. (CVE-2021-4189)

    It was discovered that Python incorrectly handled certain inputs. An attacker could possibly use this
    issue to execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS.
    (CVE-2022-0391)

    Devin Jeanpierre discovered that Python incorrectly handled sockets when the multiprocessing module was
    being used. A local attacker could possibly use this issue to execute arbitrary code and escalate
    privileges. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-42919)

    It was discovered that Python incorrectly handled certain inputs. If a user or an automated system were
    tricked into running a specially crafted input, a remote attacker could possibly use this issue to cause a
    denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 18.04 LTS and Ubuntu 22.04 LTS.
    (CVE-2022-45061, CVE-2023-24329)

    It was discovered that Python incorrectly handled certain scripts. An attacker could possibly use this
    issue to execute arbitrary code or cause a crash. This issue only affected Ubuntu 14.04 LTS and Ubuntu
    18.04 LTS. (CVE-2022-48560)

    It was discovered that Python incorrectly handled certain plist files. If a user or an automated system
    were tricked into processing a specially crafted plist file, an attacker could possibly use this issue to
    consume resources, resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
    18.04 LTS. (CVE-2022-48564)

    It was discovered that Python did not properly handle XML entity declarations in plist files. An attacker
    could possibly use this vulnerability to perform an XML External Entity (XXE) injection, resulting in a
    denial of service or information disclosure. This issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04
    LTS. (CVE-2022-48565)

    It was discovered that Python did not properly provide constant-time processing for a crypto operation. An
    attacker could possibly use this issue to perform a timing attack and recover sensitive information. This
    issue only affected Ubuntu 14.04 LTS and Ubuntu 18.04 LTS. (CVE-2022-48566)

    It was discovered that Python instances of ssl.SSLSocket were vulnerable to a bypass of the TLS handshake.
    An attacker could possibly use this issue to cause applications to treat unauthenticated received data
    before TLS handshake as authenticated data after TLS handshake. This issue only affected Ubuntu 14.04 LTS,
    Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-40217)

    It was discovered that Python incorrectly handled null bytes when normalizing pathnames. An attacker could
    possibly use this issue to bypass certain filename checks. This issue only affected Ubuntu 22.04 LTS.
    (CVE-2023-41105)

    It was discovered that Python incorrectly handled privilege with certain parameters. An attacker could
    possibly use this issue to maintain the original processes' groups before starting the new process. This
    issue only affected Ubuntu 23.10. (CVE-2023-6507)

    It was discovered that Python incorrectly handled symlinks in temp files. An attacker could possibly use
    this issue to modify the permissions of files. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
    LTS, Ubuntu 22.04 LTS and Ubuntu 23.10. (CVE-2023-6597)

    It was discovered that Python incorrectly handled certain crafted zip files. An attacker could possibly
    use this issue to crash the program, resulting in a denial of service. (CVE-2024-0450)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6891-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-48565");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.12-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.12-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-venv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.4~14.04.1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm13', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-stdlib', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-testsuite', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-stdlib', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-testsuite', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-examples', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-venv', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-examples', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-venv', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'idle-python3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-dev', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-minimal', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-stdlib', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-testsuite', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-full', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.10-0ubuntu1~20.04.10', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9-dev', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9-examples', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9-full', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9-minimal', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.9-venv', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm2', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'idle-python3.10', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'idle-python3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-dev', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-minimal', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-stdlib', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-testsuite', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-dev', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-minimal', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-stdlib', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-testsuite', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-dev', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-examples', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-full', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-minimal', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-nopie', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-venv', 'pkgver': '3.10.12-1~22.04.4', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-dev', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-examples', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-full', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-minimal', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-nopie', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.11-venv', 'pkgver': '3.11.0~rc1-1~22.04.1~esm1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'idle-python3.11', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'idle-python3.12', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.11', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.11-dev', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.11-minimal', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.11-stdlib', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.11-testsuite', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.12', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.12-dev', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.12-minimal', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.12-stdlib', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libpython3.12-testsuite', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-dev', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-examples', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-full', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-minimal', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-nopie', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.11-venv', 'pkgver': '3.11.6-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-dev', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-examples', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-full', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-minimal', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-nopie', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3.12-venv', 'pkgver': '3.12.0-1ubuntu0.1', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.10 / idle-python3.11 / idle-python3.12 / etc');
}
