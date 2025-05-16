#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191677);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/20");

  script_cve_id(
    "CVE-2023-48795",
    "CVE-2024-2215",
    "CVE-2024-2216",
    "CVE-2024-28149",
    "CVE-2024-28150",
    "CVE-2024-28151",
    "CVE-2024-28152",
    "CVE-2024-28153",
    "CVE-2024-28154",
    "CVE-2024-28155",
    "CVE-2024-28156",
    "CVE-2024-28157",
    "CVE-2024-28158",
    "CVE-2024-28159",
    "CVE-2024-28160",
    "CVE-2024-28161",
    "CVE-2024-28162"
  );
  script_xref(name:"JENKINS", value:"2024-03-06");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-03-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other
    products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the
    extension negotiation message), and a client and server may consequently end up with a connection for
    which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because
    the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and
    mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of
    ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and
    (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API
    before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80,
    AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0,
    Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15,
    SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH
    through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang
    XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd
    through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and
    LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3,
    Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server
    before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the
    mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh
    crate before 0.40.2 for Rust. (CVE-2023-48795)

  - Jenkins HTML Publisher Plugin 1.16 through 1.32 (both inclusive) does not properly sanitize input,
    allowing attackers with Item/Configure permission to implement cross-site scripting (XSS) attacks and to
    determine whether a path on the Jenkins controller file system exists. (CVE-2024-28149)

  - Jenkins HTML Publisher Plugin 1.32 and earlier does not escape job names, report names, and index page
    titles shown as part of the report frame, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2024-28150)

  - Jenkins HTML Publisher Plugin 1.32 and earlier archives invalid symbolic links in report directories on
    agents and recreates them on the controller, allowing attackers with Item/Configure permission to
    determine whether a path on the Jenkins controller file system exists, without being able to access it.
    (CVE-2024-28151)

  - In Jenkins Bitbucket Branch Source Plugin 866.vdea_7dcd3008e and earlier, except
    848.850.v6a_a_2a_234a_c81, when discovering pull requests from forks, the trust policy Forks in the same
    account allows changes to Jenkinsfiles from users without write access to the project when using
    Bitbucket Server. (CVE-2024-28152)

  - Jenkins OWASP Dependency-Check Plugin 5.4.5 and earlier does not escape vulnerability metadata from
    Dependency-Check reports, resulting in a stored cross-site scripting (XSS) vulnerability. (CVE-2024-28153)

  - Jenkins MQ Notifier Plugin 1.4.0 and earlier logs potentially sensitive build parameters as part of debug
    information in build logs by default. (CVE-2024-28154)

  - Jenkins AppSpider Plugin 1.0.16 and earlier does not perform permission checks in several HTTP endpoints,
    allowing attackers with Overall/Read permission to obtain information about available scan config names,
    engine group names, and client names. (CVE-2024-28155)

  - In Jenkins Delphix Plugin 3.0.1, a global option for administrators to enable or disable SSL/TLS
    certificate validation for Data Control Tower (DCT) connections is disabled by default. (CVE-2024-28161)

  - In Jenkins Delphix Plugin 3.0.1 through 3.1.0 (both inclusive) a global option for administrators to
    enable or disable SSL/TLS certificate validation for Data Control Tower (DCT) connections fails to take
    effect until Jenkins is restarted when switching from disabled validation to enabled validation.
    (CVE-2024-28162)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins docker-build-step Plugin 2.11 and earlier
    allows attackers to connect to an attacker-specified TCP or Unix socket URL, and to reconfigure the plugin
    using the provided connection test parameters, affecting future build step executions. (CVE-2024-2215)

  - A missing permission check in an HTTP endpoint in Jenkins docker-build-step Plugin 2.11 and earlier allows
    attackers with Overall/Read permission to connect to an attacker-specified TCP or Unix socket URL, and to
    reconfigure the plugin using the provided connection test parameters, affecting future build step
    executions. (CVE-2024-2216)

  - Jenkins Build Monitor View Plugin 1.14-860.vd06ef2568b_3f and earlier does not escape Build Monitor View
    names, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to
    configure Build Monitor Views. (CVE-2024-28156)

  - Jenkins GitBucket Plugin 0.8 and earlier does not sanitize Gitbucket URLs on build views, resulting in a
    stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure jobs.
    (CVE-2024-28157)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Subversion Partial Release Manager Plugin
    1.0.1 and earlier allows attackers to trigger a build. (CVE-2024-28158)

  - A missing permission check in Jenkins Subversion Partial Release Manager Plugin 1.0.1 and earlier allows
    attackers with Item/Read permission to trigger a build. (CVE-2024-28159)

  - Jenkins iceScrum Plugin 1.1.6 and earlier does not sanitize iceScrum project URLs on build views,
    resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure
    jobs. (CVE-2024-28160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-03-06");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - AppSpider Plugin to version 1.0.17 or later
  - Bitbucket Branch Source Plugin to version 871.v28d74e8b_4226 or later
  - Build Monitor View Plugin: See vendor advisory
  - Delphix Plugin to version 3.1.1 or later
  - docker-build-step Plugin: See vendor advisory
  - GitBucket Plugin: See vendor advisory
  - HTML Publisher Plugin to version 1.32.1 or later
  - iceScrum Plugin: See vendor advisory
  - MQ Notifier Plugin to version 1.4.1 or later
  - OWASP Dependency-Check Plugin to version 5.4.6 or later
  - Subversion Partial Release Manager Plugin: See vendor advisory
  - Trilead API Plugin to version 2.141.v284120fd0c46 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1.0.16', 'fixed_version' : '1.0.17', 'plugin' : 'AppSpider Plugin'},
    {'max_version' : '866', 'fixed_version' : '871', 'fixed_display' : '871.v28d74e8b_4226', 'plugin' : 'Bitbucket Branch Source Plugin'},
    {'max_version' : '1.14', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Build Monitor View Plugin'},
    {'min_version' : '3.0.1', 'max_version' : '3.1.0', 'fixed_version' : '3.1.1', 'fixed_display' : '3.1.1', 'plugin' : 'Delphix Plugin'},
    {'max_version' : '2.11', 'fixed_display' : 'See vendor advisory', 'plugin' : 'docker-build-step Plugin'},
    {'max_version' : '0.8', 'fixed_display' : 'See vendor advisory', 'plugin' : 'GitBucket Plugin'},
    {'max_version' : '1.32', 'fixed_version' : '1.32.1', 'plugin' : 'HTML Publisher Plugin'},
    {'max_version' : '1.1.6', 'fixed_display' : 'See vendor advisory', 'plugin' : 'iceScrum Plugin'},
    {'max_version' : '1.4.0', 'fixed_version' : '1.4.1', 'plugin' : 'MQ Notifier Plugin'},
    {'max_version' : '5.4.5', 'fixed_version' : '5.4.6', 'plugin' : 'OWASP Dependency-Check Plugin'},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Subversion Partial Release Manager Plugin'},
    {'max_version' : '2.133', 'fixed_version' : '2.141', 'fixed_display' : '2.141.v284120fd0c46', 'plugin' : 'Trilead API Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE, 'xss':TRUE}
);
