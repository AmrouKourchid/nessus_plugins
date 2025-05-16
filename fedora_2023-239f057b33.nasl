#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-239f057b33
#

include('compat.inc');

if (description)
{
  script_id(187047);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");
  script_xref(name:"FEDORA", value:"2023-239f057b33");

  script_name(english:"Fedora 38 : unrealircd (2023-239f057b33)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-239f057b33 advisory.

    # UnrealIRCd 6.1.3

    The main focus of this release is adding countermeasures against large scale spam/drones. Upstream does
    this by offering a central API which can be used for accessing Central Blocklist, Central Spamreport and
    Central Spamfilter.

    ## Enhancements
      * Central anti-spam services:
        * The services from below require a central-api key, which you can [request
    here](https://www.unrealircd.org/central-api/).
        * [Central Blocklist](https://www.unrealircd.org/docs/Central_Blocklist) is an attempt to detect and
    block spammers. It works similar to DNS Blacklists but the central blocklist receives many more details
    about the user that is trying to connect and therefore can make a better decision on whether a user is
    likely a spammer.
        * [Central Spamreport](https://www.unrealircd.org/docs/Central_spamreport) allows you to send spam
    reports (user details, last sent lines) via the `SPAMREPORT` command. This information may then be used to
    improve [Central Blocklist](https://www.unrealircd.org/docs/Central_Blocklist) and/or [Central
    Spamfilter](https://www.unrealircd.org/docs/Central_Spamfilter).
        * The [Central Spamfilter](https://www.unrealircd.org/docs/Central_Spamfilter), which provides
    `spamfilter { }` blocks that are centrally managed, is now fetched from a different URL if you have an
    Central API key set. This way, upstream can later provide `spamfilter { }` blocks that build on central
    blocklist scoring functionality, and also so upstream doesn't have to reveal all the central spamfilter
    blocks to the world.
      * New option `auto` for [set::hide-ban-reason](https://www.unrealircd.org/docs/Set_block#set::hide-ban-
    reason), which is now the default. This will hide the \*LINE reason to other users if the \*LINE reason
    contains the IP of the user, for example when it contains a DroneBL URL which has `lookup?ip=XXX`. This to
    protect the privacy of the user. Other possible settings are `no` (never hide, the previous default) and
    `yes` to always hide the \*LINE reason. In all cases the user affected by the server ban can still see the
    reason and IRCOps too.
      * Make [Deny channel](https://www.unrealircd.org/docs/Deny_channel_block) support escaped sequences like
    `channel #xyz\*;` so you can match a literal `*` or `?` via `\*` and `\?`.
      * New option [listen::options::websocket::allow-
    origin](https://www.unrealircd.org/docs/Listen_block#options_block_(optional)): this allows to restrict
    websocket connections to a list of websites (the sites hosting the HTML/JS page that makes the websocket
    connection). It doesn't *securely* restrict it though, non-browsers will bypass this restriction, but it
    can still be useful to restrict regular webchat users.
      * The [Proxy block](https://www.unrealircd.org/docs/Proxy_block) already had support for reverse
    proxying with the `Forwarded` header. Now it also properly supports `X-Forwarded-For`. If you previously
    used a proxy block with type `web`, then you now need to choose one of the new types explicitly. Note that
    using a reverse proxy for IRC traffic is rare (see the proxy block docs for details), but upstream offers
    the option.

    ## Changes
      * Reserve more file descriptors for internal use. For example, when there are 10,000 fd's are available
    upstream now reserves 250, and when 2048 are available upstream reserves 32. This so upstream has more fds
    available to handle things like log files, do HTTPS callbacks to blacklists, etc.
      * Make `$client.details` in logs follow the ident rules for users in the handshake too, so use the `~`
    prefix if ident lookups are enabled and identd fails etc.
      * More validation for operclass names (`a-zA-Z0-9_-`)
      * Hits for central-blocklist are now broadcasted globally instead of staying on the same server.

    ## Fixes
      * When using a trusted reverse proxy with the [Proxy
    block](https://www.unrealircd.org/docs/Proxy_block), under some circumstances it was possible for end-
    users to spoof IPs.
      * Crash issue when a module is reloaded (not unloaded) and that module no longer provides a particular
    moddata object, e.g. because it was renamed or no longer needed. This is rare, but did happen for one
    third party module recently.
      * Fix memory leak when unloading a module for good and that module provided ModData objects for unknown
    users (users still in the handshake).
      * Don't ask to generate TLS certificate if one already exists (issue introduced in 6.1.2).

    ## Developers and protocol
      * New hooks: `HOOKTYPE_WATCH_ADD`, `HOOKTYPE_WATCH_DEL`, `HOOKTYPE_MONITOR_NOTIFICATION`.
      * The hook `HOOKTYPE_IS_HANDSHAKE_FINISHED` is now properly called at all places.
      * A new [URL API](https://www.unrealircd.org/docs/Dev:URL_API) to easily fetch URLs from modules.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-239f057b33");
  script_set_attribute(attribute:"solution", value:
"Update the affected unrealircd package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:unrealircd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'unrealircd-6.1.3-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'unrealircd');
}
