#TRUSTED 8bae4d470ebec73dbbad96c35327d1300ab5e1762df56e193cf7688de6dea70208b441eb628c8401b4596778b291207eb5353e950c9ea6f05919ef110dc63ec69c21cc217eb1dd66ec0c2cc04bd85b2b2066fbe143533f58b1cc522cbe0a91d834a903618d7491b1c63234d0049d1163e1f98821d8a27d9a01b3f9f1001ea3bffcc7a532b3efa357ac2e5fc1129e67b2ba9db716780dd7c0d749e35dbcb41f6657194720e057f19bdd7679c2d03af9a361d032b86c9e800eec46f8de27e4d7f6b7a0e98309ce14b37f4d08d1c720ec01360389929c7c5a56926f7ecb554a9985403d85d3547ab85ccd6e9935a10ff2191099704328281d7f9accc1e254ec1fb229f255db28fc34498a959b27015fff730f3d041cf36490815acddb1ac53fe0163eb3792dff5e897f36d6b64180dbbe23b875db91790022724490232f52392cc76815b5c9bd409368f88653203e21b7ed17ef13d8e47041939ca10e13378e9312c4f3282ecf012e36856d4b9e3002dc9056dfe061741bbd4c378bcf916f1ae53b524c6f5c539de8b67f13658827a9d483bf095407ac008075d80020cd93a5a1bff26463edeb2c25f7e30a134bd0a39c0fa8735ecd7a2e3b70d52727f34602e46888ac7d04914c64c83d9bc49bcc4b867b0e11dba4acb1250ba920ef37398342ab063889d06c13ca2e03cc53793abd193f73c8ed7484e7ce600b973bcd4cbd1375
#TRUST-RSA-SHA256 6f28acd793be59d9c1d013ecddd85b47ed1f731205a0bc0658789df31193e857be8b679554a8cf9ee918df7af4f8ddb0d61cde21a719b05b6d64092a9f24c36d58226bb9cbe5733fcb05ad6a77c58f4c1ce85ef1b20dab73fc7f41edd77336e3e44b57011fe5a57f1bfa7e100d7340225937b59aa189f27577db043ed415f116839ca9ac5006370440b8434d49d7de70b3cb43ccf9046dc0fc4683e8c933ab848a2f0b9b1ec883c2b271fe1a03bcf4dce14e6970d981f52b2e2780233e50f4e6ec1dd2ab4f5ac74531c6c5eb9053e0587973708b5254eb9b0b30caabdd56c859aaeecdb76081176b267693b25ad57b8ac1bd908c81d67f048cf58d0e0772526ba1122f6b19b90d250f4e61aefe532cd6da55098aa1ecf6e09178679558d1a2bfcfb3983bc8c4333bbbdc0bd764ff44d036c4bf5ef6c50d099cc35266c950f687e8c346acc75d71c84d0e7b6121fe1e8bfcc9697fc7669f50bdf14c26d492d2b5bcf8b4a6cdcc817866e3e6991dc009a69c287133e2f06b785bdb0c593bfc15a8de7258121593cd56c3533343b11cc2c5d826bd02ad0c197c9c8212a844bf7f38aae6a8e2ca49d9b57046bbc553596cb72efd5ac62b6f96c71f9585f00ba558e79bba8b2955a232edc3061fdbb929aa53789066a5b6c9cb6eb6c157ca518cc3a6738f17394911090eed731e32d46bb46fd68195305b49de5fa05dc33512cd8c39
#%NASL_MIN_LEVEL 70300
###
# (C) Tenable Network Security, Inc.
###

include('deprecated_nasl_level.inc');
include('compat.inc');
include('host_os.inc');

if (description)
{
  script_id(33850);
  script_version("1.295");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/03");

  script_xref(name:"IAVA", value:"0001-A-0502");
  script_xref(name:"IAVA", value:"0001-A-0648");

  script_name(english:"Unix Operating System Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The operating system running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Unix operating
system running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of the Unix operating system that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info2.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

global_var global_report, last_call_succeeded;

function report(txt)
{
  last_call_succeeded = 1;
  if ( strlen(txt) > 0 )
    global_report = global_report + '\n' + txt;
}

function report_and_exit()
{
  if ( strlen(global_report) > 0 )
  {
    security_hole(port: 0, extra: global_report);
    set_kb_item(name: 'Host/OS/obsolete', value: TRUE);
    set_kb_item(name: 'Host/OS/obsolete/text', value:global_report);
  }
  exit(0);
}

# Beware of version numbers like 2.5 / 2.5.1; if 2.5.1 is not obsolete
# and 2.5 is, check the version before calling this function.
function check(os, dates, latest, url, name, cpe_part, ver_pat, note)
{
  local_var k, r, c, eos_date, item, version, tmp_name;

  if(isnull(ver_pat))
    ver_pat = "[^0-9.]([0-9.]+)[^0-9]*$";

  item = pregmatch(pattern:ver_pat, string:os);
  if(!isnull(item) && !isnull(item[1]))
    version = item[1];
  else version = 'unknown';

  r = "";
  c = TRUE;
  foreach k (keys(dates))
  {
    if (k >< os)
    {      
      if (c)
      {
        if (name && name >!< k) r = r + name + " ";

        eos_date = NULL;
        if (dates[k])
        {
          eos_date = dates[k];
          if ("extended" >< tolower(eos_date))
          {
            set_kb_item(
              name:"Host/OS/extended_support",
              value:r + k + ' support ends on ' + eos_date + '.'
            );
            exit(0, r+k+" is on extended support.");
          }
        }
        tmp_name = r + k;
        r =  r + k + ' support ended';
        if (eos_date) r = r + ' on ' +eos_date;
        r = r +'.\n';
        if (latest) r = r + 'Upgrade to ' + latest + '.\n';
        if (!empty_or_null(note)) r = r + '\n' + note + '\n';
        if (url)  r = r + '\nFor more information, see : ' + url + '\n\n';
        register_unsupported_product(
          product_name:tmp_name, 
          cpe_class:CPE_CLASS_OS,
          cpe_base:cpe_part, 
          version:version);
        report(txt: r);
      }
     }
  }
}

function check_instance()
{
  local_var v, os, os2, os3, os4, k, k2, v2, sap_flag, sles_ltss, v_ltss;

  last_call_succeeded = 0;
  os = _FCT_ANON_ARGS[0];

  #### Mandrake / Mandriva Linux ####
  # Defunct as of 2015-05-27
  # http://www.linuxtoday.com/infrastructure/2003100201126NWMDSS
  # http://www.mandriva.com/en/mandriva-product-lifetime-policy
  # http://www.mandriva.com/en/security/advisories

  v = make_array(
    "Mandriva Business Server 2", "2015-05-27", # OS DEFUNCT
    "Mandriva Business Server 1", "2015-05-27", # OS DEFUNCT
    "Mandriva Enterprise Server 5", "2014-06-16",
    "Mandriva Linux 2011",   "2013-02-28",
    "Mandriva Linux 2010.1", "2012-07-08",
    "Mandriva Linux 2010.0", "2012-11-03",
    "Mandriva Linux 2009.1", "2010-10-29",
    "Mandriva Linux 2009.0", "2011-10-15",
    "Mandriva Linux 2008.1", "2009-10-15",
    "Mandriva Linux 2008.0", "2010-10-09",
    "Mandriva Linux 2007.1", "2015-05-27", # OS DEFUNCT
    "Mandriva Linux 2007.0", "2008-04-11", # or later?
    "MDK2007.0",             "2008-04-11", # or later?
    "Mandriva Linux 2006",   "2007-04-11", # or later?
    "MDK2006",               "2007-04-11", # or later?
    "MDK10.2",               "2015-05-27", # OS DEFUNCT
    "MDK10.1",               "2006-02-22", # or later?
    "MDK10.0",               "2005-09-20", # or later?
    "MDK9.2",                "2005-03-15", # or later?
    "MDK9.1",                "2004-08-31", # or later?
    "MDK9.0",                "2004-03-31",
    "MDK8.2",                "2003-09-30",
    "MDK8.1",                "2003-03-31",
    "MDK8.0",                "2003-03-31",
    "MDK7.2",                "2003-03-31",
    "MDK7.1",                "2002-10-15", # also Corporate Server 1.0.1
    "MDK7.0",                "2001-04-18",
    "MDK6.1",                "2001-04-18",
    "MDK6",                  "2001-04-18",
    "MDK5",                  "2015-05-27" # OS DEFUNCT
    # Single Network Firewall 7.2 n/a June 1, 2003
    # Multi Network Firewall 8. n/a December 12, 2004
);

check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Mandriva",
  cpe_part: "mandriva:linux",
  ver_pat: "[^0-9.]([0-9.]+)$");

# Old Mandrake need to be tested *before* Red Hat.

os2 = get_kb_item("Host/etc/mandrake-release");
if (strlen(os2) == 0)
{
  os2 = get_kb_item("Host/etc/redhat-release");
  if ("Mandrake" >!< os2) os2 = NULL;
}

if (strlen(os2) > 0)
{
 foreach k (keys(v))
 {
   k2 = str_replace(find: "MDK", replace: "release ", string: k);
   v2[k2] = v[k];
 }
 check(
   os: os2,
   dates: v2,
   name: "Linux Mandrake",
   url: "https://en.wikipedia.org/wiki/Mandriva",
   cpe_part: "mandriva:linux");
}

#### Mageia ####

v = make_array(
  # "Mageia 7",   "2020-12-30",         # https://www.mageia.org/en/support/ & https://advisories.mageia.org/7.html
  "Mageia 6",   "2019-09-30",         # https://www.mageia.org/en/support/ & https://advisories.mageia.org/6.html
  "Mageia 5",   "2017-12-31",           # https://www.mageia.org/en/support/
  "Mageia 4",   "2015-09-19",           # https://www.mageia.org/en/support/
  "Mageia 3",   "2014-11-26",           # http://blog.mageia.org/en/2014/11/26/lets-say-goodbye-to-mageia-3/
  "Mageia 2",   "2013-11-22",           # http://blog.mageia.org/en/2013/11/21/farewell-mageia-2/
  "Mageia 1",   "2012-12-01"            # http://blog.mageia.org/en/2012/12/02/mageia-1-eol/
);

check(
  os: os,
  dates: v,
  latest: "Mageia 6",
  url: "http://www.mageia.org/en/support/",
  cpe_part: "mageia:linux");

# DR OS - based off CentOS and follows the same lifecycle policy
if (os =~ "^(Dell|Quest) DR[0-9]+")
{
  os2 = get_kb_item("Host/OS/HTTP");
  if (!empty_or_null(os2) && "CentOS" >< os2)
  {
    os += " (" + os2 + ")";
    check(
      os     : os,
      dates  : v,
      latest : "CentOS 8 / 7",
      note   : "Note that DR OS is based off CentOS and follows the same lifecycle policy.",
      url    : "http://www.nessus.org/u?e63bc1c5",
      cpe_part : "centos:centos"
    );
  }
}

#### Scientific Linux ####
# Policies seem to indicate that they will follow RedHat's dates for EOL/EOS.
v = make_array (
#  "Scientific Linux 7", "2024-06-30",
  "Scientific Linux 6", "2020-11-30", # https://scientificlinux.org/downloads/sl-versions/sl6/
  "Scientific Linux 5", "2017-03-31", # https://en.wikipedia.org/wiki/Scientific_Linux, https://scientificlinuxforum.org/index.php?showtopic=3590.
  "Scientific Linux 4", "2012-02-29", # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=SCIENTIFIC-LINUX-ANNOUNCE&P=R262&1=SCIENTIFIC-LINUX-ANNOUNCE&9=A&J=on&d=No+Match%3BMatch%3BMatches&z=4
  "Scientific Linux 3", "2010-10-10"
);
check(
  os     : os,
  dates  : v,
  latest : "Scientific Linux 7",
  url    : "https://www.scientificlinux.org/downloads/sl-versions/",
  cpe_part : "fermilab:scientific_linux"
  );


##
#  SuSE Linux
#  has been removed from here as it is now covered by seol plugins
##


#### Gentoo Linux ####
# testing Gentoo does not make sense - but we may have a look at the profile
# See also gentoo_unmaintained_packages.nasl


#### Slackware ####
v = make_array(
  # Per ftp://ftp.slackware.com/pub/slackware/slackware-12.0/ChangeLog.txt (see entry for June 14th, 2012):
  #
  # Effective August 1, 2012, security patches will no longer be     #
  # provided for the following versions of Slackware (which will all #
  # be more than 5 years old at that time):                          #
  # Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2, 11.0, 12.0.           #
  "Slackware 13.37",     "2018-07-05", # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 13.1",     "2018-07-05",  # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 13.0",     "2018-07-05",  # https://en.wikipedia.org/wiki/Slackware#Releases
  "Slackware 12.2",     "2012-12-09", # ftp://ftp.slackware.com/pub/slackware/slackware-12.1/ChangeLog.txt
  "Slackware 12.1",     "2013-12-09", # ftp://ftp.slackware.com/pub/slackware/slackware-12.1/ChangeLog.txt
  "Slackware 12.0",     "2012-08-01",
  "Slackware 11.0",     "2012-08-01",
  "Slackware 10.2",     "2012-08-01",
  "Slackware 10.1",     "2012-08-01",
  "Slackware 10.0",     "2012-08-01",
  "Slackware 9.1",      "2012-08-01",
  "Slackware 9.0",      "2012-08-01",
  "Slackware 8.1",      "2012-08-01"
);

check(
  os     : os,
  dates  : v,
  latest : 'Slackware 14.2',
  url    : "ftp://ftp.slackware.com/pub/slackware/slackware-12.0/ChangeLog.txt (see entry for June 14th, 2012)",
  cpe_part : "slackware:slackware_linux");

#### AIX ####
# http://en.wikipedia.org/wiki/AIX_operating_system

v = make_array(
  # "AIX 7.2", "2021-09-30 (end of standard support) / extended support is ongoing)", # https://www.ibm.com/support/pages/aix-support-lifecycle-information
  "AIX 7.1", "2023-04-30", # https://www.ibm.com/support/pages/aix-support-lifecycle-information
  "AIX 6.1", "2017-04-30", # Only paid service is available https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=MT303077WWEN
  "AIX 5.3", "2015-04-30",
  "AIX 5.2", "2009-04-30",
  "AIX 5.1", "2006-04-01",
  "AIX 4", "",
  "AIX 3", "");

check(
  os: os,
  dates: v,
  latest: "AIX 7.2 / 7.3",
  url: "http://www-01.ibm.com/software/support/aix/lifecycle/index.html",
  cpe_part: "ibm:aix");

#### HP-UX ####
# http://www.hp.com/softwarereleases/releases-media2/notices/0303.htm
# http://www.hp.com/softwarereleases/releases-media2/latest/06_08/0806_Update_letter.pdf
v = make_array(
  "HP-UX 10.20", "2003-07-01",
  "HP-UX 11.0", "2006-12-31", # (designated with VUF number B.11.00)
  "HP-UX B.11.00", "2006-12-31", # Not sure we store it like this
  # "HP-UX 11i??", "2003-03-01", # HP-UX 11i Version 1.5 for Itanium
  "HP-UX 7", "",
  "HP-UX 8", "",
  "HP-UX 9", "",
  "HP-UX 10", "2003-07-01" );

check(
  os: os,
  dates: v,
  latest: "HP-UX 11i V3",
  url: "https://www.hpe.com/global/softwarereleases/releases-media2/HPEredesign/pages/overview.html",
  cpe_part: "hp:hp-ux");

#### IRIX ####
v = make_array(
  "IRIX ", "2013-12-31");
check(
  os:os,
  dates:v,
  url:"https://web.archive.org/web/20150401201054/http://www.sgi.com/tech/irix/",
  cpe_part: "sgi:irix");

#### Solaris ####

# http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml
# http://web.archive.org/web/20060820024218/http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml
# http://www.sun.com/service/eosl/eosl_solaris.html

v = make_array(

  # nb: "For customers with a current support contract for the Oracle
  #     Solaris 8 release, new Severity 1 fixes and new security fixes
  #     will be available for the period of July 2012 - October 2014."
  #    from http://www.oracle.com/us/support/library/hardware-systems-support-policies-069182.pdf
  #
  # nb: from https://blogs.oracle.com/patch/entry/solaris_9_exiting_extended_support,
  #     "there will be a final patch release cycle in November for both
  #     Solaris 8 and Solaris 9..."
  # "Solaris 10", "2024-01-31", # https://blogs.oracle.com/solaris/great-news-about-extended-support-for-oracle-solaris-10-os
  "Solaris 9", "2014-10-31",
  "Solaris 8", "2014-10-31",
  "Solaris 7", "2005-08-15",
  "Solaris 2.6", "2003-07-23",
  "Solaris 2.5.1", "2002-09-22",
  "Solaris 2.5", "2000-12-27",
  "Solaris 2.4", "2000-09-30",
  "Solaris 2.3", "1999-06-01",
  "Solaris 2.2", "1996-05-01",
  "Solaris 2.1", "1996-04-15",
  "Solaris 2.0", "1996-01-01",
  "Solaris 1.4", "2000-09-30",
  # 1.3_U1 in fact
  "Solaris 1.3", "2000-09-30",
  # Solaris 1.1 & C 06/03/96
  "Solaris 1.2", "2000-01-06",
  "Solaris 1.1", "2000-01-06",
  "Solaris 1.0", "1999-09-30" );

check(
  os: os,
  dates: v,
  latest: "Solaris 11",
  url: "http://www.oracle.com/us/support/library/lifetime-support-hardware-301321.pdf",
  cpe_part: "sun:solaris");

#### FreeBSD ####
# http://www.auscert.org.au/render.html?it=9392
# http://www.daemonology.net/blog/2006-10-01-upcoming-freebsd-eols.html
# https://www.freebsd.org/security/unsupported.html
v = make_array(
  "FreeBSD 3",    "",
  "FreeBSD 4",    "2007-01-31",   # latest stable in the 4 series
  "FreeBSD 4.11", "2007-01-31",
  "FreeBSD 5",    "2008-05-31",   # latest stable in the 5 series
  "FreeBSD 5.3",  "2006-10-31",
  "FreeBSD 5.4",  "2006-10-31",
  "FreeBSD 5.5",  "2008-05-31",
  "FreeBSD 6",    "2010-11-30",   # latest stable in the 6 series
  "FreeBSD 6.0",  "2006-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 6.1",  "2008-05-31",
  "FreeBSD 6.2",  "2008-05-31",
  "FreeBSD 6.3",  "2010-01-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-October/005353.html
  "FreeBSD 6.4",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 7",    "2013-02-28",   # latest in the 7 series
  "FreeBSD 7.0",  "2009-04-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-April/005205.html
  "FreeBSD 7.1",  "2011-02-28",   # http://lists.freebsd.org/pipermail/freebsd-security/2011-January/005771.html
  "FreeBSD 7.2",  "2010-06-30",   # http://lists.freebsd.org/pipermail/freebsd-announce/2010-June/001325.html
  "FreeBSD 7.3",  "2012-03-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2012-March/006202.html
  "FreeBSD 7.4",  "2012-02-28",
  "FreeBSD 8",    "2015-08-01",   # latest stable in the 8 series
  "FreeBSD 8.0",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "FreeBSD 8.1",  "2012-07-31",
  "FreeBSD 8.2",  "2012-07-31",
  "FreeBSD 8.3",  "2014-04-30",
  "FreeBSD 8.4",  "2015-08-01",   # https://lists.freebsd.org/pipermail/freebsd-announce/2015-August/001664.html
  "FreeBSD 9",    "2016-12-31",   # latest stable in the 9 series
  "FreeBSD 9.0",  "2013-03-31",
  "FreeBSD 9.1",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "FreeBSD 9.2",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "FreeBSD 9.3",  "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10",   "2018-10-31",   # latest stable in the 10 series
  "FreeBSD 10.0", "2015-03-02",   # http://lists.freebsd.org/pipermail/freebsd-announce/2015-March/001630.html
  "FreeBSD 10.1", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10.2", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "FreeBSD 10.3", "2018-04-30",
  "FreeBSD 10.4", "2018-10-31",
  "FreeBSD 11",   "2021-09-30",   # latest stable in the 11 series
  "FreeBSD 11.0", "2017-11-30",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-December/001816.html
  "FreeBSD 11.1", "2018-09-30",
  "FreeBSD 11.2", "2019-10-31",   # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 11.3", "2020-09-30",   # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 11.4", "2021-09-30",   # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 12.0", "2020-02-29",   # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 12.1", "2021-01-31",   # https://www.freebsd.org/security/unsupported.html
  "FreeBSD 12.2", "2022-03-31",   # https://www.freebsd.org/security/unsupported/
  "FreeBSD 12.3", "2023-03-31",   # https://www.freebsd.org/security/unsupported/
  "FreeBSD 13.0", "2022-08-31",   # https://www.freebsd.org/security/unsupported/
  "FreeBSD 13.1", "2023-07-31"    # https://www.freebsd.org/security/unsupported/
);

os2 = get_kb_item("Host/FreeBSD/release");
if (os2)
  check(
    os: str_replace(string: os2, find: "FreeBSD-", replace: "FreeBSD "),
    dates: v,
    latest: "FreeBSD 13 / 13.2 / 14 / 14.0.",
    url: "https://www.freebsd.org/security/",
    cpe_part: "freebsd:freebsd");
else
  check(
    os: os,
    dates: v,
    latest: "FreeBSD 13 / 13.2 / 14 / 14.0",
    url: "https://www.freebsd.org/security/",
    cpe_part: "freebsd:freebsd");

#### NetBSD ####
v = make_array(
  "NetBSD 7.0",  "2020-06-30", # http://www.netbsd.org/releases/formal.html
  "NetBSD 6.1",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd1
  "NetBSD 6.0",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd1
  "NetBSD 5.2",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 5.1",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 5.0",  "2015-11-09",          # https://blog.netbsd.org/tnf/entry/end_of_life_for_netbsd
  "NetBSD 4.0",  "2012-11-17",          # http://mail-index.netbsd.org/netbsd-announce/2012/10/27/msg000162.html
  "NetBSD 3.1",  "2009-05-29",          # http://mail-index.netbsd.org/netbsd-announce/2009/05/30/msg000066.html
  "NetBSD 3.0",  "2009-05-29",          # http://mail-index.netbsd.org/netbsd-announce/2009/05/30/msg000066.html
  "NetBSD 2.1",  "2008-04-30",          # http://mail-index.netbsd.org/netbsd-announce/2008/05/01/msg000025.html
  "NetBSD 2.0",  "2008-04-30",          # http://mail-index.netbsd.org/netbsd-announce/2008/05/01/msg000025.html
  "NetBSD 1.6",  "",
  "NetBSD 1.5",  "",
  "NetBSD 1.4",  "",
  "NetBSD 1.3",  "",
  "NetBSD 1.2",  "",
  "NetBSD 1.1",  "",
  "NetBSD 1.0",  "",
  "NetBSD 0.9",  "",
  "NetBSD 0.8",  ""
);

check(
  os     : os,
  dates  : v,
  latest : "NetBSD 8.1 / 9.1",
  url    : "http://www.netbsd.org/releases/formal.html",
  cpe_part : "netbsd:netbsd");

#### OpenBSD ####
# only the two most recent versions are actively supported
# according to http://www.openbsd.org/faq/faq5.html#Flavors
# https://en.wikipedia.org/wiki/OpenBSD_version_history

v = make_array(
# "OpenBSD 6.8", "2021-10-31", # still supported - https://endoflife.software/operating-systems/unix-like-bsd/openbsd
  "OpenBSD 6.7", "2021-05-31",
  "OpenBSD 6.6", "2020-10-18",
  "OpenBSD 6.5", "2020-05-19",
  "OpenBSD 6.4", "2019-10-17",
  "OpenBSD 6.3", "2019-05-03",
  "OpenBSD 6.2", "2018-10-18",
  "OpenBSD 6.1", "2018-04-15",
  "OpenBSD 6.0", "2017-10-09",
  "OpenBSD 5.9", "2017-04-11",
  "OpenBSD 5.8", "2016-09-01",
  "OpenBSD 5.7", "2015-03-29",
  "OpenBSD 5.6", "2015-10-18",
  "OpenBSD 5.5", "2015-04-30",
  "OpenBSD 5.4", "2014-11-01",
  "OpenBSD 5.3", "2014-05-01",
  "OpenBSD 5.2", "2013-11-01",
  "OpenBSD 5.1", "2013-05-01",
  "OpenBSD 5.0", "2012-11-01",
  "OpenBSD 4.9", "2012-05-01",
  "OpenBSD 4.8", "2011-11-01",
  "OpenBSD 4.7", "2011-05-01",
  "OpenBSD 4.6", "2010-11-01",
  "OpenBSD 4.5", "2010-05-19",
  "OpenBSD 4.4", "2009-10-18",
  "OpenBSD 4.3", "2009-05-01",
  "OpenBSD 4.2", "2008-11-01",
  "OpenBSD 4.1", "2008-06-30",
  "OpenBSD 4.0", "2007-11-01",
  "OpenBSD 3.9", "2007-06-30",
  "OpenBSD 3.8", "2006-11-13",
  "OpenBSD 3.7", "2006-05-18",
  "OpenBSD 3.6", "2006-10-30",
  "OpenBSD 3.5", "2005-06-30",
  "OpenBSD 3.4", "2004-10-30",
  "OpenBSD 3.3", "2004-05-05",
  "OpenBSD 3.2", "2003-11-04",
  "OpenBSD 3.1", "2003-06-01",
  "OpenBSD 3.0", "2002-12-01",
  "OpenBSD 2.9", "2002-06-01",
  "OpenBSD 2.", "",
  "OpenBSD 1.", "" );

check(
  os: os,
  dates: v,
  latest: "OpenBSD 6.9",
  url: "http://www.openbsd.org/security.html",
  cpe_part: "openbsd:openbsd");

#### Tru64 UNIX (and its earlier incarnations) ####
v = make_array(
  "Tru64 UNIX 5.1B-6", "2012-12-31 (end of standard support) / extended support is ongoing)",  # http://h30097.www3.hp.com/ees.html (for MPS w/o SE)
  "Tru64 UNIX 5.1B-5", "2012-12-31",  # http://h30097.www3.hp.com/tru64roadmap.pdf
  "Tru64 UNIX 5.1B-4", "2010-10-30",  # http://h30097.www3.hp.com/tru64roadmap.pdf
  "Tru64 UNIX 5.1B-3", "",
  "Tru64 UNIX 5.1B-2", "",
  "Tru64 UNIX 5.1B-1", "",
  # "Tru64 UNIX 5.1B",  we should flag this too but that might catch 5.1B-6
  "Tru64 UNIX 5.1A", "",
  # "Tru64 UNIX 5.1",  we should flag this too but that might catch 5.1B-6
  "Tru64 UNIX 5.0", "",
  "Tru64 UNIX 4.", "",
  "Digital UNIX", "",
  "DEC OSF/", ""
);
check(
  os:os,
  dates:v,
  url:"https://en.wikipedia.org/wiki/Tru64_UNIX",
  cpe_part: "hp:tru64");

#### Other very old distros ####
# uname:
# Linux CorelLinux 2.2.12 #1 SMP Tue Nov 9 14:11:25 EST 1999 i686 unknown

v = make_array("Corel Linux", "");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Corel_Linux",
  cpe_part: "corel:linux");

v = make_array("OpenLinux", "");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Caldera_OpenLinux",
  cpe_part: "caldera:openlinux");

v = make_array("Trustix", "2007-12-31");
check(
  os: os,
  dates: v,
  url: "https://en.wikipedia.org/wiki/Trustix",
  cpe_part: "trustix:secure_linux");


  # ========= VMware ESXi
  # ref: VMWare Full product Lifecycle Matrix
  # url: https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/support/product-lifecycle-matrix.pdf
  v = make_array(
    "VMware ESXi 1", "",
    "VMware ESXi 2", "",
    "VMware ESXi 3", "2010-05-21",
    "VMware ESXi 4", "2013-08-15",
    "VMware ESXi 5", "2018-09-19", 
    "VMware ESXi 6.0", "2022-03-12" 
    # "VMware ESXi 6.5", "2023-11-15"
    # "VMware ESXi 6.7", "2023-11-15"
    # "VMware ESXi 7.0", "2027-04-02"
    );

  check(
    os: ereg_replace(string:os, pattern:"VMware ESX Server \di ", replace:"VMware ESXi "),
    dates: v,
    latest: "VMware ESXi 6.7.0 build-10764712",
    url: "https://docs.vmware.com/en/VMware-vSphere/",
    cpe_part: "vmware:esxi");

  # ========= Oracle Linux
  local_var oracleVersion;
  local_var short_os = os;

  local_var isOracleLinux = get_kb_item("Host/OracleLinux");
  # is this oracle linux?
  if ( !isnull(isOracleLinux) )
  {
    # oracle linux, need to simplify mess of names
    oracleVersion = pregmatch( pattern:'[^0-9.]([0-9.]+)[^0-9.]*$', string:os );
    # can simplify?
    if ( !isnull(oracleVersion) )
    {
      # simplified, run check on Oracle Linux
      short_os = "Oracle Linux " + oracleVersion[1];
    }
    v = make_array(
      # https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
      "Oracle Linux 1", "",
      "Oracle Linux 2", "",
      "Oracle Linux 3", "2011-10-01",
      "Oracle Linux 4", "2013-02-01",
      "Oracle Linux 5", "2017-06-01",
      "Oracle Linux 6", "2021-03-01"
      # "Oracle Linux 7.", "2024-07-01",
      # "Oracle Linux 8.", "2029-07-01"
      );
    check(
      os: short_os,
      dates: v,
      # 7.x Release Notes : https://docs.oracle.com/en/operating-systems/oracle-linux/7/
      # 8.x Release Notes : https://docs.oracle.com/en/operating-systems/oracle-linux/8/
      latest: "Oracle Linux 7.9 / 8.4", 
      url: "https://yum.oracle.com/whatsnew.html",
      cpe_part: "oracle:linux");
  }

  # ========= Oracle VM Server
  # simplify mess of names
  local_var oracleVmVersion = pregmatch( pattern:'Oracle VM.*[^0-9.]([0-9.]+)', string:os );
  # was simplified?
  if ( !isnull(oracleVmVersion) )
  {
    # simplified, run check on Oracle VM Server
    short_os = "Oracle VM Server " + oracleVmVersion[1];
    v = make_array(
      "Oracle VM Server 1.", "",
      "Oracle VM Server 2.", "2015-11-01");
    check(
      os: short_os,
      dates: v,
      latest: "Oracle VM Server 3.4.6",
      url: "https://yum.oracle.com/whatsnew.html",
      cpe_part: "oracle:vm_server");
  }
}

os = get_kb_item("Host/OS");
if (host_os_id_uncertain()) os = NULL; # Avoid FP
if (os && '\n' >< os) os = split(os, keep:FALSE);
else if (strlen(os)) os = make_list(os);
else os = make_list();

# Handle very old distros
if (max_index(os) == 0 && max_index(keys(get_kb_list("Host/etc/*"))) == 0)
  exit(0);

rep = '';
var instance;

foreach instance (os)
{
 check_instance(instance);
 if (last_call_succeeded == 0) exit(0, "The remote OS is still supported.");
}

report_and_exit();
