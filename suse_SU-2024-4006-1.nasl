#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4006-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212581);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2024-47533", "CVE-2024-49502", "CVE-2024-49503");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4006-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Proxy and Retail Branch Server 4.3 (SUSE-SU-2024:4006-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4006-1 advisory.

    cobbler:

    - Security issues fixed:

      * CVE-2024-47533: Prevent privilege escalation from none to admin (bsc#1231332)

    - Other bugs fixed:

      * Increase start timeout for cobblerd unit (bsc#1219450)
      * Provide sync_single_system for DHCP modules to improve performance (bsc#1219450)
      * Add input_string_*, input_boolean, input_int functions to public API
      * Add new setting for Uyuni authentication endpoint (bsc#1219887)

    grafana-formula:

    - Version 0.11.0
      * Add SLES 15 SP6 to supported versions (bsc#1228286)

    inter-server-sync:

    - Version 0.3.5-0
      * Decode boolean values for export (bsc#1228545)

    saltboot-formula:

    - Update to version 0.1.1723628891.ffb1da5
      * Rework request stop function to avoid unnecessary warnings
        (bsc#1212985)

    spacecmd:

    - Version 4.3.29-0
      * Speed up softwarechannel_removepackages (bsc#1227606)

    spacewalk-backend:

    - Version 4.3.30-0
      * Make ISSv1 timezone independent (bsc#1221505)
      * reposync: introduce timeout when syncing DEB channels (bsc#1225960)
      * yum_src: use proper name variable name for subprocess.TimeoutExpired
      * Check and populate PTF attributes at the time of importing
        packages (bsc#1225619)
      * reposync: import GPG keys to RPM DB individually (bsc#1217003)
      * Add log string to the journal when services are stopped
        because of insufficient disk space

    spacewalk-certs-tools:

    - Version 4.3.26-0
      * Fix private key format in jabberd certificate file (bsc#1228851)
      * Fix parsing Authority Key Identifier when keyid is not prefixed (bsc#1229079)
      * Support multiple certificates for root-ca-file and server-cert-file

    spacewalk-client-tools:

    - Version 4.3.21-0
      * Update translation strings

    spacewalk-config:

    - Version 4.3.14-0
      * Trust the Content-Length header from AJP (bsc#1226439)

    spacewalk-java:

    - Version 4.3.82-0
      * Limit frontend-log message size (bsc#1231900)
    - Version 4.3.81-0
      * Add detection of Ubuntu 24.04
    - Version 4.3.80-0
      * Use custom select instead of errata view for better performance
        (bsc#1225619)
    - Version 4.3.79-0
      * Add info URL for cobbler to clean the system profile (bsc#1219645)
      * Require correct scap packages for Ubuntu
      * Require correct scap packages for Debian 12 (bsc#1227746)
      * Fix finding system_checkin_threshold configuration value on Sytems
        Overview page (bsc#1224108)
      * Allow changing base channel to SUSE Liberty Linux LTSS when the system is on
        Liberty (bsc#1228326)
      * Implement product migration from RHEL and Clones to SUSE Liberty
        Linux
      * Remove system also from proxy SSH known_hosts (bsc#1228345)
      * Fix NullPointerException when generating subscription matcher
        input (bsc#1228638)
      * Allow free products and SUSE Manager Proxy being managed by SUSE Manager
        Server PAYG
      * Open bootstrap script directory URL in a new page (bsc#1225603)
      * Delay package list refresh when Salt was updated (bsc#1217978)
      * Add SLE Micro 5 to the list of systems which support monitoring (bsc#1227334)
      * Add all SLE Micro systems to the list of systems which get PTF repositories
      * Update last sync refresh timestamp only when at least one time products
        were synced before
      * Prevent NullPointerException when listing history events without completion
        time (bsc#1146701)
      * Autoinstallation: prevent issues with duplicate IP address due to some
        networks (bsc#1226461)
      * Improve SQL queries and performance to check for PTF packages (bsc#1225619)
      * Check the correct Salt package before product migration (bsc#1224209)
      * Fix the date format output when using the HTTP API to use ISO 8601
        format (bsc#1227543)
      * Fix transactional update check for SL Micro (bsc#1227406)
      * Improve score comparison in system search to fix ISE (bsc#1228412)
      * Fix package profile update on CentOS 7 when yum-utils is not
        installed (bsc#1227133)

    spacewalk-utils:

    - Version 4.3.22-0
      * Add repositories for Ubuntu 24.04 LTS
    - Version 4.3.21-0
      * Drop unsupported tool spacewalk-final-archive as it is broken
        and may disclose sensitive information (bsc#1228945)

    spacewalk-web:

    - Security issues fixed:

      * Version 4.3.42-0
        + CVE-2024-49503: Escape organization credentials username to
          mitigate XSS vulnerability (bsc#1231922)
      * Version 4.3.41-0
        + CVE-2024-49502: Validate proxy hostname format and escape proxy
          username to mitigate XSS vulnerabilities (bsc#1231852)

    - Bugs fixed:

      * Version 4.3.40-0
        + Fix channel selection using SSM (bsc#1226917)
        + Fix datetime selection when using maintenance windows (bsc#1228036)

    susemanager:

    - Version 4.3.39-0
      * Enable bootstrapping for Ubuntu 24.04 LTS
    - Version 4.3.38-0
      * Add missing package python3-ply to bootstrap repo definition (bsc#1228130)
      * Create special bootstrap data for SUSE Manager Server 4.3 with LTSS
        updates for Hub scenario (bsc#1211899)
      * Add LTSS updates to SUSE Manager Proxy 4.3 bootstrap data
      * Add traditional stack to boostrap repo on sles15sp6 (bsc#1228147)
      * Change package to libdbus-glib-1-2 on sle15sp6 (bsc#1228147)

    susemanager-build-keys:

    - Extended 2048 bit SUSE SLE 12, 15 GA-SP5 key until 2028. (bsc#1229339)

    susemanager-docs_en:

    - Documented Ubuntu 24.04 LTS as a supported client OS in Client
    - SUSE Manager 4.3.14 documentation update
    - In network ports section, deleted partially outdated image, added
      port 443 for clients, and removed Cobbler only used internally
      (bsc#1217338)
    - Added installer-updates.suse.com to the list of URLs in Installation
      and Upgrade Guide (bsc#1229178)
    - Enhanced instructions about the permissions for the IAM role
      in Public Cloud Guide
    - Fixed OS minor number in Client Configuration Guide (bsc#1218090)
    - Added warning about Package Hub (bsc#1221435)
    - Removed Verify Packages section from Package Management chapter
      in Client Configuration Guide
    - Added note about usernames in PAM section in Administration Guide
      (bsc#1227599)
    - Updated Content Lifecycle Management (CLM) examples for Red Hat
      Enterprise Linux 9 (bsc#1226687)
    - Added VM based proxy installation in Installation and Upgrade Guide
    - Fixed PostgreSQL name entity
    - Improved Large Deployments Guide with better tuning values and
      extra parameters added
    - Updated lists of SUSE Linux Enterprise hardening profiles in openSCAP
      chapter in the Administration Guide

    susemanager-schema:

    - Version 4.3.27-0
      * Introduce new attributes to detect PTF packages (bsc#1225619)

    susemanager-sls:

    - Version 4.3.45-0
      * Start using DEB822 format for repository sources beginning with Ubuntu 24.04
    - Version 4.3.44-0
      * Speed-up mgrutil.remove_ssh_known_host runner (bsc#1223312)
      * Implement product migration from RHEL and clones to SUSE Liberty Linux
      * Disable transactional-update.timer on SLEM at bootstrap
      * Explicitly remove old venv-minion environment when updating Python versions
      * sumautil: properly detect bridge interfaces (bsc#1226461)
      * Fix typo on directories to clean up when deleting a system (bsc#1228101)
      * Translate GPG URL if it has server name and client behind proxy
        (bsc#1223988)
      * Fix yum-utils package missing on CentOS7 minions (bsc#1227133)
      * Implement IMDSv2 for AWS instance detection (bsc#1226090)
      * Fix package profile update on CentOS 7 when yum-utils is not
        installed (bsc#1227133)
      * Fix parsing passwords with special characters for PostgreSQL
        exporter

    susemanager-sync-data:

    - Version 4.3.21-0
      * Add SLES15-SP5-LTSS channel families
      * Add MicroOS PPC channel family
    - Version 4.3.20-0
      * Add Ubuntu 24.04 support
    - Version 4.3.19-0
      * Fix CentOS 7 repo urls (bsc#1227526)
      * Add channel family for SLES 12 SP5 LTSS Extended Security
      * Implement product migration from RHEL and clones to SUSE Liberty Linux

    uyuni-common-libs:

    - Version 4.3.11-0
      * Enforce directory permissions at repo-sync when creating
        directories (bsc#1229260)
      * Make ISSv1 timezone independent (bsc#1221505)

    uyuni-reportdb-schema:

    - Version 4.3.11-0
      * Change Errata CVE column to type text as a varchar reaches the
        maximum (bsc#1226478)

    How to apply this update:

    1. Log in as root user to the SUSE Manager Server.
    2. Stop the Spacewalk service:
    `spacewalk-service stop`
    3. Apply the patch using either zypper patch or YaST Online Update.
    4. Start the Spacewalk service:
    `spacewalk-service start`

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231922");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e8d8f1e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49503");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47533");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-49503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cobbler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grafana-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:inter-server-sync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-uyuni-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:saltboot-formula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-base-minimal-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-package-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-proxy-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-utils-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-build-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-build-keys-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-docs_en-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-schema-utility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-sls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-sync-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:susemanager-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-config-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-proxy-systemd-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-reportdb-schema");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'mgr-daemon-4.3.11-150400.3.21.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-certs-tools-4.3.26-150400.3.36.7', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-spacewalk-check-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-client-setup-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'python3-spacewalk-client-tools-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-uyuni-common-libs-4.3.11-150400.3.21.6', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacecmd-4.3.29-150400.3.42.8', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-minimal-4.3.42-150400.3.52.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-minimal-config-4.3.42-150400.3.52.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-certs-tools-4.3.26-150400.3.36.7', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-check-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-client-setup-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-client-tools-4.3.21-150400.3.33.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-proxy-broker-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-proxy-common-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-proxy-management-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-proxy-package-manager-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-proxy-redirect-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'spacewalk-proxy-salt-4.3.19-150400.3.29.9', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'susemanager-build-keys-15.4.10-150400.3.29.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-build-keys-web-15.4.10-150400.3.29.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'uyuni-proxy-systemd-services-4.3.14-150000.1.27.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'cobbler-3.3.3-150400.5.52.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'grafana-formula-0.11.0-150400.3.21.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'inter-server-sync-0.3.5-150400.3.36.13', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'python3-uyuni-common-libs-4.3.11-150400.3.21.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'saltboot-formula-0.1.1723628891.ffb1da5-150400.3.18.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-app-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-applet-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-common-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-config-files-tool-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-iss-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-iss-export-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-package-push-server-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-server-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-sql-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-sql-postgresql-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-tools-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-xml-export-libs-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-backend-xmlrpc-4.3.30-150400.3.47.16', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-base-4.3.42-150400.3.52.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-config-4.3.14-150400.3.18.6', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-html-4.3.42-150400.3.52.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-4.3.82-150400.3.96.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-config-4.3.82-150400.3.96.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-lib-4.3.82-150400.3.96.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-java-postgresql-4.3.82-150400.3.96.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-taskomatic-4.3.82-150400.3.96.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-utils-4.3.22-150400.3.29.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'spacewalk-utils-extras-4.3.22-150400.3.29.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-4.3.39-150400.3.58.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-docs_en-4.3.14-150400.9.66.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-docs_en-pdf-4.3.14-150400.9.66.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-schema-4.3.27-150400.3.45.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-schema-utility-4.3.27-150400.3.45.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-sls-4.3.45-150400.3.55.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-sync-data-4.3.21-150400.3.35.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'susemanager-tools-4.3.39-150400.3.58.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'uyuni-config-modules-4.3.45-150400.3.55.4', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'uyuni-reportdb-schema-4.3.11-150400.3.18.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cobbler / grafana-formula / inter-server-sync / mgr-daemon / etc');
}
