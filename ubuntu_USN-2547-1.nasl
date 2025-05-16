#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2547-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82074);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2011-0992",
    "CVE-2012-3543",
    "CVE-2015-2318",
    "CVE-2015-2319",
    "CVE-2015-2320"
  );
  script_bugtraq_id(
    47208,
    55251,
    73250,
    73253,
    73256
  );
  script_xref(name:"USN", value:"2547-1");

  script_name(english:"Ubuntu 14.04 LTS : Mono vulnerabilities (USN-2547-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2547-1 advisory.

    It was discovered that the Mono TLS implementation was vulnerable to the SKIP-TLS vulnerability. A remote
    attacker could possibly use this issue to perform client impersonation attacks. (CVE-2015-2318)

    It was discovered that the Mono TLS implementation was vulnerable to the FREAK vulnerability. A remote
    attacker or a machine-in-the-middle could possibly use this issue to force the use of insecure
    ciphersuites. (CVE-2015-2319)

    It was discovered that the Mono TLS implementation still supported a fallback to SSLv2. This update
    removes the functionality as use of SSLv2 is known to be insecure. (CVE-2015-2320)

    It was discovered that Mono incorrectly handled memory in certain circumstances. A remote attacker could
    possibly use this issue to cause Mono to crash, resulting in a denial of service, or to obtain sensitive
    information. This issue only applied to Ubuntu 12.04 LTS. (CVE-2011-0992)

    It was discovered that Mono incorrectly handled hash collisions. A remote attacker could possibly use this
    issue to cause Mono to crash, resulting in a denial of service. This issue only applied to Ubuntu 12.04
    LTS. (CVE-2012-3543)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2547-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2320");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-accessibility2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-accessibility4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-c5-1.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cairo2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cairo4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cecil-private-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-codecontracts4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-compilerservices-symbolwriter4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-corlib4.5-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-cscompmgd8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-csharp4.0c-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-custommarshalers4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-data-tds4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-db2-1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-debugger-soft2.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-debugger-soft4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-entityframework-sqlserver6.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-entityframework6.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-cjk4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-mideast4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-other4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-rare4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-west2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n-west4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n4.0-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-i18n4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-management2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-messaging-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-messaging-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build-engine4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build-framework4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build-tasks-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build-utilities-v4.0-4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-build4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-csharp4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-visualc10.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft-web-infrastructure1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-microsoft8.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-npgsql4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-opensystem-c4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-oracle4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-parallel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi2.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-peapi4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-posix2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-posix4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-profiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-rabbitmq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-rabbitmq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-relaxng2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-relaxng4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-security2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip2.6-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip2.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sharpzip4.84-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-simd2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-simd4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sqlite2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-sqlite4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-componentmodel-composition4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-componentmodel-dataannotations4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-configuration-install4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-configuration4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-core4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-datasetextensions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-linq2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-services-client4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-services2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-data4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-drawing-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-drawing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-dynamic4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-enterpriseservices4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-identitymodel-selectors4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-identitymodel4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-io-compression-filesystem4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-io-compression4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-json-microsoft4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-json2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-json4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-ldap-protocols4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-ldap2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-ldap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-management4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-messaging2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-messaging4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-net-http-formatting4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-net-http-webrequest4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-net-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-net2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-net4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-numerics4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-core2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-debugger2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-experimental2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-interfaces2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-linq2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-observable-aliases0.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-platformservices2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-providers2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-runtime-remoting2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-windows-forms2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-reactive-windows-threading2.2-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime-caching4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime-durableinstancing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime-serialization-formatters-soap4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-runtime4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-security4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-servicemodel-activation4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-servicemodel-discovery4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-servicemodel-routing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-servicemodel-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-servicemodel4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-serviceprocess4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-threading-tasks-dataflow4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-transactions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-abstractions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-applicationservices4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-dynamicdata4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-extensions-design4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-extensions4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-http-selfhost4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-http-webhost4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-http4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-mvc1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-mvc2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-mvc3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-routing4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-services4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-webpages-deployment2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-webpages-razor2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web-webpages2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-windows-forms-datavisualization4.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-windows-forms4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-windows4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-xaml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-xml-linq4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-xml-serialization4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system-xml4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-system4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-tasklets2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-tasklets4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-wcf3.0a-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-web4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-webbrowser2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-webbrowser4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-webmatrix-data4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-windowsbase3.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-windowsbase4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-winforms2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-xbuild-tasks2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-xbuild-tasks4.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmonoboehm-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmonoboehm-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmonosgen-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmonosgen-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-2.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-4.0-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-4.0-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-csharp-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-dmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-gmcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-mcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime-boehm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime-sgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-xbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'libmono-2.0-1', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-2.0-dev', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-accessibility2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-accessibility4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-c5-1.1-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-cairo2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-cairo4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-cecil-private-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-cil-dev', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-codecontracts4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-compilerservices-symbolwriter4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-corlib2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-corlib4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-corlib4.5-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-cscompmgd8.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-csharp4.0c-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-custommarshalers4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-data-tds2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-data-tds4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-db2-1.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-debugger-soft2.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-debugger-soft4.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-entityframework-sqlserver6.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-entityframework6.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-http4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-cjk4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-mideast4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-other4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-rare4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-west2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n-west4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n4.0-all', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-i18n4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-ldap2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-ldap4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-management2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-management4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-messaging-rabbitmq2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-messaging-rabbitmq4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-messaging2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-messaging4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build-engine4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build-framework4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build-tasks-v4.0-4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build-utilities-v4.0-4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-build4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-csharp4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-visualc10.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft-web-infrastructure1.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-microsoft8.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-npgsql2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-npgsql4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-opensystem-c4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-oracle2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-oracle4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-parallel4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-peapi2.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-peapi4.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-posix2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-posix4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-profiler', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-rabbitmq2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-rabbitmq4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-relaxng2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-relaxng4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-security2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-security4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-sharpzip2.6-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-sharpzip2.84-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-sharpzip4.84-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-simd2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-simd4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-sqlite2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-sqlite4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-componentmodel-composition4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-componentmodel-dataannotations4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-configuration-install4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-configuration4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-core4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-datasetextensions4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-linq2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-linq4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-services-client4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-services2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data-services4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-data4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-design4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-drawing-design4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-drawing4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-dynamic4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-enterpriseservices4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-identitymodel-selectors4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-identitymodel4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-io-compression-filesystem4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-io-compression4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-json-microsoft4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-json2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-json4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-ldap-protocols4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-ldap2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-ldap4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-management4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-messaging2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-messaging4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-net-http-formatting4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-net-http-webrequest4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-net-http4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-net2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-net4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-numerics4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-core2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-debugger2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-experimental2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-interfaces2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-linq2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-observable-aliases0.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-platformservices2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-providers2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-runtime-remoting2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-windows-forms2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-reactive-windows-threading2.2-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime-caching4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime-durableinstancing4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime-serialization-formatters-soap4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime-serialization4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-runtime4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-security4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-servicemodel-activation4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-servicemodel-discovery4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-servicemodel-routing4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-servicemodel-web4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-servicemodel4.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-serviceprocess4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-threading-tasks-dataflow4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-transactions4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-abstractions4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-applicationservices4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-dynamicdata4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-extensions-design4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-extensions4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-http-selfhost4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-http-webhost4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-http4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-mvc1.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-mvc2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-mvc3.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-razor2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-routing4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-services4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-webpages-deployment2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-webpages-razor2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web-webpages2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-web4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-windows-forms-datavisualization4.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-windows-forms4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-windows4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-xaml4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-xml-linq4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-xml-serialization4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system-xml4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-system4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-tasklets2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-tasklets4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-wcf3.0a-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-web4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-webbrowser2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-webbrowser4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-webmatrix-data4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-windowsbase3.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-windowsbase4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-winforms2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-xbuild-tasks2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono-xbuild-tasks4.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmono2.0-cil', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmonoboehm-2.0-1', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmonoboehm-2.0-dev', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmonosgen-2.0-1', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'libmonosgen-2.0-dev', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-2.0-gac', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-2.0-service', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-4.0-gac', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-4.0-service', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-complete', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-csharp-shell', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-devel', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-dmcs', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-gac', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-gmcs', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-jay', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-mcs', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-runtime', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-runtime-boehm', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-runtime-common', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-runtime-sgen', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-utils', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'mono-xbuild', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'monodoc-base', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'monodoc-manual', 'pkgver': '3.2.8+dfsg-4ubuntu1.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmono-2.0-1 / libmono-2.0-dev / libmono-accessibility2.0-cil / etc');
}
