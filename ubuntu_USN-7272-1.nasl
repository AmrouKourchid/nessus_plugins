#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7272-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216425);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2022-24894",
    "CVE-2022-24895",
    "CVE-2023-46734",
    "CVE-2024-50340",
    "CVE-2024-50341",
    "CVE-2024-50342",
    "CVE-2024-50343",
    "CVE-2024-50345",
    "CVE-2024-51996"
  );
  script_xref(name:"USN", value:"7272-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS : Symfony vulnerabilities (USN-7272-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-7272-1 advisory.

    Soner Sayakci discovered that Symfony incorrectly handled cookie storage in the web cache. An attacker
    could possibly use this issue to obtain sensitive information and access unauthorized resources.
    (CVE-2022-24894)

    Marco Squarcina discovered that Symfony incorrectly handled the storage of user session information. An
    attacker could possibly use this issue to perform a cross-site request forgery (CSRF) attack.
    (CVE-2022-24895)

    Pierre Rudloff discovered that Symfony incorrectly checked HTML input. An attacker could possibly use this
    issue to perform cross site scripting. (CVE-2023-46734)

    Vladimir Dusheyko discovered that Symfony incorrectly sanitized special input with a PHP directive in URL
    query strings. An attacker could possibly use this issue to expose sensitive information or cause a denial
    of service. This issue only affected Ubuntu 24.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-50340)

    Oleg Andreyev, Antoine Makdessi, and Moritz Rauch discovered that Symfony incorrectly handled user
    authentication. An attacker could possibly use this issue to access unauthorized resources and expose
    sensitive information. This issue was only addressed in Ubuntu 24.04 LTS. (CVE-2024-50341, CVE-2024-51996)

    Linus Karlsson and Chris Smith discovered that Symfony returned internal host information during host
    resolution. An attacker could possibly use this issue to obtain sensitive information. This issue only
    affected Ubuntu 24.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-50342)

    It was discovered that Symfony incorrectly parsed user input through regular expressions. An attacker
    could possibly use this issue to expose sensitive information. (CVE-2024-50343)

    Sam Mush discovered that Symfony incorrectly parsed URIs with special characters. An attacker could
    possibly use this issue to perform phishing attacks. (CVE-2024-50345)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7272-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-all-my-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-amazon-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-amazon-sns-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-amazon-sqs-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-amqp-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-asset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-asset-mapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-bandwidth-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-beanstalkd-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-brevo-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-brevo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-browser-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-chatwork-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-click-send-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-clickatell-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-clock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-contact-everyone-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-crowdin-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-css-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-debug-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dependency-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-discord-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dom-crawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-dotenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-engagespot-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-error-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-esendex-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-event-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-expo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-expression-language");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-fake-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-fake-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-firebase-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-forty-six-elks-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-framework-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-free-mobile-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-gateway-api-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-gitter-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-go-ip-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-google-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-google-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-http-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-http-foundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-inflector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-infobip-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-infobip-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-iqsms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-isendpro-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-kaz-info-teh-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-light-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-line-notify-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-linked-in-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-loco-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-lokalise-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mail-pace-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailchimp-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailer-send-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailgun-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailjet-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mailjet-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mastodon-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mattermost-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mercure-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-message-bird-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-message-media-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-microsoft-teams-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-mobyt-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-monolog-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-nexmo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-novu-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-ntfy-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-octopush-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-oh-my-smtp-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-one-signal-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-options-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-orange-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-ovh-cloud-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-pager-duty-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-password-hasher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-phpunit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-phrase-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-plivo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-postmark-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-property-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-property-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-proxy-manager-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-psr-http-message-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-pushover-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-rate-limiter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-redis-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-redlink-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-remote-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-ring-central-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-rocket-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-scaleway-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-csrf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-guard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-security-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sendberry-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sendgrid-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sendinblue-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sendinblue-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-simple-textin-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sinch-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-slack-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sms-biuras-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sms-factor-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-sms77-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-smsapi-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-smsc-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-smsmode-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-spot-hit-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-stopwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-string");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-telegram-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-telnyx-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-termii-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-turbo-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twig-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twig-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twilio-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-twitter-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-uid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-var-dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-var-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-vonage-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-link");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-profiler-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-web-server-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-webhook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-workflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-yunpian-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-zendesk-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-symfony-zulip-notifier");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '20.04', 'pkgname': 'php-symfony', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-amazon-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-asset', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-browser-kit', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-cache', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-config', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-console', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-css-selector', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-debug', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-debug-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dependency-injection', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dom-crawler', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-dotenv', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-event-dispatcher', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-expression-language', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-filesystem', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-finder', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-form', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-framework-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-google-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-client', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-foundation', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-http-kernel', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-inflector', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-intl', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-ldap', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-lock', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailchimp-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mailgun-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-messenger', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-mime', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-monolog-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-options-resolver', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-phpunit-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-postmark-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-process', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-property-access', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-property-info', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-proxy-manager-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-routing', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-core', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-csrf', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-guard', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-security-http', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-sendgrid-mailer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-serializer', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-stopwatch', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-templating', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-translation', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-twig-bridge', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-twig-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-validator', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-var-dumper', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-var-exporter', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-link', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-profiler-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-web-server-bundle', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-workflow', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'php-symfony-yaml', 'pkgver': '4.3.8+dfsg-1ubuntu1+esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-all-my-sms-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-amazon-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-amazon-sns-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-amazon-sqs-messenger', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-amqp-messenger', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-asset', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-beanstalkd-messenger', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-browser-kit', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-cache', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-clickatell-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-config', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-console', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-crowdin-translation-provider', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-css-selector', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-debug-bundle', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-dependency-injection', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-discord-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-dom-crawler', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-dotenv', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-error-handler', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-esendex-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-event-dispatcher', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-expo-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-expression-language', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-fake-chat-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-fake-sms-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-filesystem', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-finder', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-firebase-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-form', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-framework-bundle', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-free-mobile-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-gateway-api-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-gitter-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-google-chat-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-google-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-http-client', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-http-foundation', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-http-kernel', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-inflector', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-infobip-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-intl', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-iqsms-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-ldap', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-light-sms-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-linked-in-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-lock', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-loco-translation-provider', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-lokalise-translation-provider', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mailchimp-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mailgun-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mailjet-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mailjet-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mattermost-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mercure-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-message-bird-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-message-media-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-messenger', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-microsoft-teams-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mime', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-mobyt-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-monolog-bridge', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-nexmo-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-octopush-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-oh-my-smtp-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-one-signal-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-options-resolver', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-ovh-cloud-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-password-hasher', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-phpunit-bridge', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-postmark-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-process', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-property-access', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-property-info', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-proxy-manager-bridge', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-rate-limiter', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-redis-messenger', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-rocket-chat-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-routing', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-runtime', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-security-bundle', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-security-core', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-security-csrf', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-security-guard', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-security-http', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-semaphore', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sendgrid-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sendinblue-mailer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sendinblue-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-serializer', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sinch-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-slack-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sms-biuras-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-sms77-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-smsapi-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-smsc-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-spot-hit-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-stopwatch', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-string', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-telegram-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-telnyx-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-templating', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-translation', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-turbo-sms-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-twig-bridge', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-twig-bundle', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-twilio-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-uid', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-validator', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-var-dumper', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-var-exporter', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-vonage-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-web-link', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-web-profiler-bundle', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-workflow', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-yaml', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-yunpian-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'php-symfony-zulip-notifier', 'pkgver': '5.4.4+dfsg-1ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-all-my-sms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-amazon-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-amazon-sns-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-amazon-sqs-messenger', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-amqp-messenger', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-asset', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-asset-mapper', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-bandwidth-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-beanstalkd-messenger', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-brevo-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-brevo-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-browser-kit', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-cache', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-chatwork-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-click-send-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-clickatell-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-clock', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-config', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-console', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-contact-everyone-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-crowdin-translation-provider', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-css-selector', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-debug-bundle', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-dependency-injection', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-discord-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-dom-crawler', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-dotenv', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-engagespot-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-error-handler', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-esendex-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-event-dispatcher', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-expo-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-expression-language', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-fake-chat-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-fake-sms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-filesystem', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-finder', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-firebase-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-form', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-forty-six-elks-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-framework-bundle', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-free-mobile-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-gateway-api-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-gitter-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-go-ip-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-google-chat-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-google-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-html-sanitizer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-http-client', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-http-foundation', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-http-kernel', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-infobip-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-infobip-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-intl', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-iqsms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-isendpro-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-kaz-info-teh-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-ldap', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-light-sms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-line-notify-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-linked-in-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-lock', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-loco-translation-provider', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-lokalise-translation-provider', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mail-pace-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailchimp-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailer-send-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailgun-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailjet-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mailjet-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mastodon-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mattermost-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mercure-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-message-bird-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-message-media-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-messenger', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-microsoft-teams-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mime', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-mobyt-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-monolog-bridge', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-novu-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-ntfy-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-octopush-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-oh-my-smtp-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-one-signal-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-options-resolver', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-orange-sms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-ovh-cloud-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-pager-duty-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-password-hasher', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-phpunit-bridge', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-phrase-translation-provider', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-plivo-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-postmark-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-process', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-property-access', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-property-info', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-proxy-manager-bridge', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-psr-http-message-bridge', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-pushover-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-rate-limiter', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-redis-messenger', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-redlink-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-remote-event', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-ring-central-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-rocket-chat-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-routing', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-runtime', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-scaleway-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-scheduler', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-security-bundle', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-security-core', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-security-csrf', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-security-http', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-semaphore', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sendberry-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sendgrid-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sendinblue-mailer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sendinblue-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-serializer', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-simple-textin-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sinch-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-slack-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sms-biuras-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sms-factor-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-sms77-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-smsapi-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-smsc-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-smsmode-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-spot-hit-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-stopwatch', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-string', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-telegram-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-telnyx-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-templating', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-termii-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-translation', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-turbo-sms-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-twig-bridge', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-twig-bundle', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-twilio-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-twitter-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-uid', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-validator', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-var-dumper', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-var-exporter', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-vonage-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-web-link', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-web-profiler-bundle', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-webhook', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-workflow', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-yaml', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-yunpian-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-zendesk-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '24.04', 'pkgname': 'php-symfony-zulip-notifier', 'pkgver': '6.4.5+dfsg-3ubuntu3+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-symfony / php-symfony-all-my-sms-notifier / etc');
}
