#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145135);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");

  script_name(english:"EulerOS 2.0 SP3 : pcp (EulerOS-SA-2021-1106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the pcp packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A Improper Control of Generation of Code vulnerability
    in the packaging of pcp of SUSE Linux Enterprise High
    Performance Computing 15-ESPOS, SUSE Linux Enterprise
    High Performance Computing 15-LTSS, SUSE Linux
    Enterprise Module for Development Tools 15, SUSE Linux
    Enterprise Module for Development Tools 15-SP1, SUSE
    Linux Enterprise Module for Open Buildservice
    Development Tools 15, SUSE Linux Enterprise Server
    15-LTSS, SUSE Linux Enterprise Server for SAP 15, SUSE
    Linux Enterprise Software Development Kit 12-SP4, SUSE
    Linux Enterprise Software Development Kit 12-SP5
    openSUSE Leap 15.1 allows the user pcp to run code as
    root by placing it into /var/log/pcp/configs.sh This
    issue affects: SUSE Linux Enterprise High Performance
    Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise High Performance Computing
    15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux
    Enterprise Module for Development Tools 15 pcp versions
    prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for
    Development Tools 15-SP1 pcp versions prior to
    4.3.1-3.5.3. SUSE Linux Enterprise Module for Open
    Buildservice Development Tools 15 pcp versions prior to
    3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp
    versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise
    Server for SAP 15 pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise Software Development Kit 12-SP4
    pcp versions prior to 3.11.9-6.14.1. SUSE Linux
    Enterprise Software Development Kit 12-SP5 pcp versions
    prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp versions
    prior to 4.3.1-lp151.2.3.1.(CVE-2019-3695)

  - A Improper Limitation of a Pathname to a Restricted
    Directory vulnerability in the packaging of pcp of SUSE
    Linux Enterprise High Performance Computing 15-ESPOS,
    SUSE Linux Enterprise High Performance Computing
    15-LTSS, SUSE Linux Enterprise Module for Development
    Tools 15, SUSE Linux Enterprise Module for Development
    Tools 15-SP1, SUSE Linux Enterprise Module for Open
    Buildservice Development Tools 15, SUSE Linux
    Enterprise Server 15-LTSS, SUSE Linux Enterprise Server
    for SAP 15, SUSE Linux Enterprise Software Development
    Kit 12-SP4, SUSE Linux Enterprise Software Development
    Kit 12-SP5 openSUSE Leap 15.1 allows local user pcp to
    overwrite arbitrary files with arbitrary content. This
    issue affects: SUSE Linux Enterprise High Performance
    Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise High Performance Computing
    15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux
    Enterprise Module for Development Tools 15 pcp versions
    prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for
    Development Tools 15-SP1 pcp versions prior to
    4.3.1-3.5.3. SUSE Linux Enterprise Module for Open
    Buildservice Development Tools 15 pcp versions prior to
    3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp
    versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise
    Server for SAP 15 pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise Software Development Kit 12-SP4
    pcp versions prior to 3.11.9-6.14.1. SUSE Linux
    Enterprise Software Development Kit 12-SP5 pcp versions
    prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp versions
    prior to 4.3.1-lp151.2.3.1.(CVE-2019-3696)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c499b5fa");
  script_set_attribute(attribute:"solution", value:
"Update the affected pcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3695");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["pcp-3.10.6-2.h1",
        "pcp-compat-3.10.6-2.h1",
        "pcp-conf-3.10.6-2.h1",
        "pcp-doc-3.10.6-2.h1",
        "pcp-export-pcp2graphite-3.10.6-2.h1",
        "pcp-gui-3.10.6-2.h1",
        "pcp-libs-3.10.6-2.h1",
        "pcp-pmda-activemq-3.10.6-2.h1",
        "pcp-pmda-apache-3.10.6-2.h1",
        "pcp-pmda-bash-3.10.6-2.h1",
        "pcp-pmda-bonding-3.10.6-2.h1",
        "pcp-pmda-cisco-3.10.6-2.h1",
        "pcp-pmda-dbping-3.10.6-2.h1",
        "pcp-pmda-dm-3.10.6-2.h1",
        "pcp-pmda-ds389-3.10.6-2.h1",
        "pcp-pmda-ds389log-3.10.6-2.h1",
        "pcp-pmda-elasticsearch-3.10.6-2.h1",
        "pcp-pmda-gfs2-3.10.6-2.h1",
        "pcp-pmda-gluster-3.10.6-2.h1",
        "pcp-pmda-gpfs-3.10.6-2.h1",
        "pcp-pmda-gpsd-3.10.6-2.h1",
        "pcp-pmda-json-3.10.6-2.h1",
        "pcp-pmda-kvm-3.10.6-2.h1",
        "pcp-pmda-lmsensors-3.10.6-2.h1",
        "pcp-pmda-logger-3.10.6-2.h1",
        "pcp-pmda-lustre-3.10.6-2.h1",
        "pcp-pmda-lustrecomm-3.10.6-2.h1",
        "pcp-pmda-mailq-3.10.6-2.h1",
        "pcp-pmda-memcache-3.10.6-2.h1",
        "pcp-pmda-mounts-3.10.6-2.h1",
        "pcp-pmda-mysql-3.10.6-2.h1",
        "pcp-pmda-named-3.10.6-2.h1",
        "pcp-pmda-netfilter-3.10.6-2.h1",
        "pcp-pmda-news-3.10.6-2.h1",
        "pcp-pmda-nfsclient-3.10.6-2.h1",
        "pcp-pmda-nginx-3.10.6-2.h1",
        "pcp-pmda-nvidia-gpu-3.10.6-2.h1",
        "pcp-pmda-pdns-3.10.6-2.h1",
        "pcp-pmda-postfix-3.10.6-2.h1",
        "pcp-pmda-postgresql-3.10.6-2.h1",
        "pcp-pmda-roomtemp-3.10.6-2.h1",
        "pcp-pmda-rpm-3.10.6-2.h1",
        "pcp-pmda-sendmail-3.10.6-2.h1",
        "pcp-pmda-shping-3.10.6-2.h1",
        "pcp-pmda-summary-3.10.6-2.h1",
        "pcp-pmda-trace-3.10.6-2.h1",
        "pcp-pmda-unbound-3.10.6-2.h1",
        "pcp-pmda-weblog-3.10.6-2.h1",
        "pcp-pmda-zswap-3.10.6-2.h1",
        "pcp-system-tools-3.10.6-2.h1",
        "perl-PCP-PMDA-3.10.6-2.h1",
        "python-pcp-3.10.6-2.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
