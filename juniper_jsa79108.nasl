#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193216);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id(
    "CVE-2018-1000120",
    "CVE-2018-1000122",
    "CVE-2020-8284",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-38545",
    "CVE-2023-38546"
  );
  script_xref(name:"JSA", value:"JSA79108");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA79108)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA79108 advisory.

  - This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to
    pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting
    done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected
    to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due
    to this bug, the local variable that means let the host resolve the name could get the wrong value
    during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target
    buffer instead of copying just the resolved address there. The target buffer being a heap based buffer,
    and the host name coming from the URL that curl has been told to operate with. (CVE-2023-38545)

  - This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the
    specific series of conditions are met. libcurl performs transfers. In its API, an application creates
    easy handles that are the individual handles for single transfers. libcurl provides a function call that
    duplicates en easy handle called
    [curl_easy_duphandle](https://curl.se/libcurl/c/curl_easy_duphandle.html). If a transfer has cookies
    enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the
    actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned
    version of the handle would instead store the file name as `none` (using the four ASCII letters, no
    quotes). Subsequent use of the cloned handle that does not explicitly set a source to load cookies from
    would then inadvertently load cookies from a file named `none` - if such a file exists and is readable in
    the current directory of the program using libcurl. And if using the correct file format of course.
    (CVE-2023-38546)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality fail when multiple URLs are requested serially. Using its HSTS support, curl can be
    instructed to use HTTPS instead of using an insecure clear-text HTTP step even when HTTP is provided in
    the URL. This HSTS mechanism would however surprisingly be ignored by subsequent transfers when done on
    the same command line because the state would not be properly carried on. (CVE-2023-23914)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using its HSTS
    support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when
    HTTP is provided in the URL. This HSTS mechanism would however surprisingly fail when multiple transfers
    are done in parallel as the HSTS cache file gets overwritten by the most recently completed transfer. A
    later HTTP-only transfer to the earlier host name would then *not* get upgraded properly to HSTS.
    (CVE-2023-23915)

  - A malicious server can use the FTP PASV response to trick curl 7.73.0 and earlier into connecting back to
    a given IP address and port, and this way potentially make curl extract information about services that
    are otherwise private and not disclosed, for example doing port scanning and service banner extractions.
    (CVE-2020-8284)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed?r=59&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06cd5d1b");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories?r=59&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?150809e9");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Multiple-cURL-vulnerabilities-resolved
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c07d7e31");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process?r=59&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f118a206");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000120");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R1', 'fixed_display':'21.2R1, 21.2R3-S8, 21.4R3-S5, 22.3R2-S2, 22.3R3, 22.4R2-S1, 22.4R3, 23.4R1-S1, 23.4R2'},
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'21.4R3', 'fixed_ver':'21.4R3-S8'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2R3', 'fixed_ver':'22.2R3-S2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-S1-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-S1-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
