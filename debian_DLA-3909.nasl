#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3909. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(208100);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2022-23132",
    "CVE-2022-23133",
    "CVE-2022-24349",
    "CVE-2022-24917",
    "CVE-2022-24918",
    "CVE-2022-24919",
    "CVE-2022-35229",
    "CVE-2022-35230",
    "CVE-2022-43515",
    "CVE-2023-29449",
    "CVE-2023-29450",
    "CVE-2023-29454",
    "CVE-2023-29455",
    "CVE-2023-29456",
    "CVE-2023-29457",
    "CVE-2023-29458",
    "CVE-2023-32721",
    "CVE-2023-32722",
    "CVE-2023-32724",
    "CVE-2023-32726",
    "CVE-2023-32727",
    "CVE-2024-22114",
    "CVE-2024-22116",
    "CVE-2024-22119",
    "CVE-2024-22122",
    "CVE-2024-22123",
    "CVE-2024-36460",
    "CVE-2024-36461"
  );

  script_name(english:"Debian dla-3909 : zabbix-agent - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3909 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3909-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    October 03, 2024                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : zabbix
    Version        : 1:5.0.44+dfsg-1+deb11u1
    CVE ID         : CVE-2022-23132 CVE-2022-23133 CVE-2022-24349 CVE-2022-24917
                     CVE-2022-24918 CVE-2022-24919 CVE-2022-35229 CVE-2022-35230
                     CVE-2022-43515 CVE-2023-29449 CVE-2023-29450 CVE-2023-29454
                     CVE-2023-29455 CVE-2023-29456 CVE-2023-29457 CVE-2023-29458
                     CVE-2023-32721 CVE-2023-32722 CVE-2023-32724 CVE-2023-32726
                     CVE-2023-32727 CVE-2024-22114 CVE-2024-22116 CVE-2024-22119
                     CVE-2024-22122 CVE-2024-22123 CVE-2024-36460 CVE-2024-36461
    Debian Bug     : 1014992 1014994 1026847 1053877 1055175 1078553

    Several security vulnerabilities have been discovered in zabbix, a network
    monitoring solution, potentially among other effects allowing XSS, Code
    Execution, information disclosure, remote code execution, impersonation or
    session hijacking.

    As the version uploaded is a new upstrea maintainance version, there a a
    few minor new features and behavioural changes with this version. Please
    see below for further information.

    CVE-2022-23132

        During Zabbix installation from RPM, DAC_OVERRIDE SELinux capability is
        in use to access PID files in [/var/run/zabbix] folder. In this case,
        Zabbix Proxy or Server processes can bypass file read, write and execute
        permissions check on the file system level

    CVE-2022-23133

        An authenticated user can create a hosts group from the configuration
        with XSS payload, which will be available for other users. When XSS is
        stored by an authenticated malicious actor and other users try to search
        for groups during new host creation, the XSS payload will fire and the
        actor can steal session cookies and perform session hijacking to
        impersonate users or take over their accounts.

    CVE-2022-24349

        An authenticated user can create a hosts group from the configuration
        with XSS payload, which will be available for other users. When XSS is
        stored by an authenticated malicious actor and other users try to search
        for groups during new host creation, the XSS payload will fire and the
        actor can steal session cookies and perform session hijacking to
        impersonate users or take over their accounts.

    CVE-2022-24917

        An authenticated user can create a link with reflected Javascript code
        inside it for services page and send it to other users. The payload can
        be executed only with a known CSRF token value of the victim, which is
        changed periodically and is difficult to predict. Malicious code has
        access to all the same objects as the rest of the web page and can make
        arbitrary modifications to the contents of the page being displayed to a
        victim during social engineering attacks.

    CVE-2022-24918

        An authenticated user can create a link with reflected Javascript code
        inside it for items page and send it to other users. The payload can be
        executed only with a known CSRF token value of the victim, which is
        changed periodically and is difficult to predict. Malicious code has
        access to all the same objects as the rest of the web page and can make
        arbitrary modifications to the contents of the page being displayed to a
        victim during social engineering attacks.

    CVE-2022-24919

        An authenticated user can create a link with reflected Javascript code
        inside it for graphs page and send it to other users. The payload can
        be executed only with a known CSRF token value of the victim, which is
        changed periodically and is difficult to predict. Malicious code has
        access to all the same objects as the rest of the web page and can make
        arbitrary modifications to the contents of the page being displayed to a
        victim during social engineering attacks.

    CVE-2022-35229

        An authenticated user can create a link with reflected Javascript code
        inside it for the discovery page and send it to other users. The payload
        can be executed only with a known CSRF token value of the victim, which
        is changed periodically and is difficult to predict.

    CVE-2022-35230

        An authenticated user can create a link with reflected Javascript code
        inside it for the graphs page and send it to other users. The payload
        can be executed only with a known CSRF token value of the victim, which
        is changed periodically and is difficult to predict.

    CVE-2022-43515

        Zabbix Frontend provides a feature that allows admins to maintain the
        installation and ensure that only certain IP addresses can access it. In
        this way, any user will not be able to access the Zabbix Frontend while
        it is being maintained and possible sensitive data will be prevented
        from being disclosed.  An attacker can bypass this protection and access
        the instance using IP address not listed in the defined range.

    CVE-2023-29449

        JavaScript preprocessing, webhooks and global scripts can cause
        uncontrolled CPU, memory, and disk I/O utilization.
        Preprocessing/webhook/global script configuration and testing are only
        available to Administrative roles (Admin and Superadmin). Administrative
        privileges should be typically granted to users who need to perform
        tasks that require more control over the system. The security risk is
        limited because not all users have this level of access.

    CVE-2023-29450

        JavaScript pre-processing can be used by the attacker to gain access to
        the file system (read-only access on behalf of user zabbix) on the
        Zabbix Server or Zabbix Proxy, potentially leading to unauthorized
        access to sensitive data.

    CVE-2023-29454

        A Stored or persistent cross-site scripting (XSS) vulnerability was
        found on Users section in Media tab in Send to form field.  When
        new media is created with malicious code included into field Send to
        then it will execute when editing the same media.

    CVE-2023-29455

        A Reflected XSS attacks, also known as non-persistent attacks, was found
        where an attacker can pass malicious code as GET request to graph.php
        and system will save it and will execute when current graph page is
        opened.

    CVE-2023-29456

        URL validation scheme receives input from a user and then parses it to
        identify its various components. The validation scheme can ensure that
        all URL components comply with internet standards.

    CVE-2023-29457

        A Reflected XSS attacks, also known as non-persistent attacks, was found
        where XSS session cookies could be revealed, enabling a perpetrator to
        impersonate valid users and abuse their private accounts.

    CVE-2023-29458

        Duktape is an 3rd-party embeddable JavaScript engine, with a focus on
        portability and compact footprint. When adding too many values in
        valstack JavaScript will crash. This issue occurs due to bug in Duktape
        2.6 which is an 3rd-party solution that we use.

    CVE-2023-32721

        A stored XSS has been found in the Zabbix web application in the Maps
        element if a URL field is set with spaces before URL.

    CVE-2023-32722

        The zabbix/src/libs/zbxjson module is vulnerable to a buffer overflow
        when parsing JSON files via zbx_json_open.

    CVE-2023-32724

        Memory pointer is in a property of the Ducktape object. This leads to
        multiple vulnerabilities related to direct memory access and
        manipulation.

    CVE-2023-32726

        Possible buffer overread from reading DNS responses.

    CVE-2023-32727

        An attacker who has the privilege to configure Zabbix items can use
        function icmpping() with additional malicious command inside it to
        execute arbitrary code on the current Zabbix server.

    CVE-2024-22114

        A user with no permission to any of the Hosts can access and view host
        count & other statistics through System Information Widget in Global
        View Dashboard.

    CVE-2024-22116

        An administrator with restricted permissions can exploit the script
        execution functionality within the Monitoring Hosts section. The lack of
        default escaping for script parameters enabled this user ability to
        execute arbitrary code via the Ping script, thereby compromising
        infrastructure.

    CVE-2024-22119

        Stored XSS in graph items select form

    CVE-2024-22122

        Zabbix allows to configure SMS notifications. AT command injection
        occurs on Zabbix Server because there is no validation of Number
        field on Web nor on Zabbix server side. Attacker can run test of SMS
        providing specially crafted phone number and execute additional AT
        commands on the modem.

    CVE-2024-22123

        Setting SMS media allows to set GSM modem file. Later this file is used
        as Linux device. But due everything is a file for Linux, it is possible
        to set another file, e.g. log file and zabbix_server will try to
        communicate with it as modem. As a result, log file will be broken with
        AT commands and small part for log file content will be leaked to UI.

    CVE-2024-36460

        The front-end audit log allows viewing of unprotected plaintext
        passwords, where the passwords are displayed in plain text.

    CVE-2024-36461

        Direct access to memory pointers within the JS engine for modification.
        This vulnerability allows users with access to a single item
        configuration (limited role) to compromise the whole infrastructure of
        the monitoring solution by remote code execution.

    For Debian 11 bullseye, these problems have been fixed in version
    1:5.0.44+dfsg-1+deb11u1.

    We recommend that you upgrade your zabbix packages.

    For the detailed security status of zabbix please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/zabbix

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

    As stated above, this version is a new upstream maintaince release.
    Upstream's upgrade notes lists the following changes:
    (Changes not relevant for Debian bullseye have been omitted.)

    Upgrade notes for 5.0.11

        VMware event collector - The behavior of VMware event collector has been
        changed to fix a memory overload issue.

    Upgrade notes for 5.0.31

        Improved performance of history syncers

        The performance of history syncers has been improved by introducing a
        new read-write lock. This reduces locking between history syncers,
        trappers and proxy pollers by using a shared read lock while accessing
        the configuration cache. The new lock can be write  locked only by the
        configuration syncer performing a configuration cache reload.

    Upgrade notes for 5.0.32

        The following limits for JavaScript objects in preprocessing have been
        introduced:

        The total size of all messages that can be logged with the Log() method
        has been limited to 8 MB per script execution.
        The initialization of multiple CurlHttpRequest objects has been limited
        to 10 per script execution.  The total length of header fields that can
        be added to a single CurlHttpRequest object with the AddHeader() method
        has been limited to 128 Kbytes (special characters and header names
        included).

    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/zabbix");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23132");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23133");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24917");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24918");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-35229");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-35230");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43515");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29449");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29450");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29457");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32721");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32726");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32727");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22114");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22116");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22119");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36460");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36461");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/zabbix");
  script_set_attribute(attribute:"solution", value:
"Upgrade the zabbix-agent packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23132");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43515");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-frontend-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-proxy-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zabbix-server-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'zabbix-agent', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-frontend-php', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-java-gateway', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-mysql', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-pgsql', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-proxy-sqlite3', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-server-mysql', 'reference': '1:5.0.44+dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'zabbix-server-pgsql', 'reference': '1:5.0.44+dfsg-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix-agent / zabbix-frontend-php / zabbix-java-gateway / etc');
}
