#
# (C) Tenable 2019 
# 
# os_eol.inc
# Revision 1.0
#

global_var _latest_supported = make_array(
  "CentOS",  "CentOS 6 / 7",
  "Fedora",  "Fedora 28 / 29",
  "FreeBSD", "FreeBSD 11.2 / 12.0",
  "Ubuntu",  "Ubuntu 14.04 / 16.04 / 18.04 / 18.10",
  "VMware",  "VMware ESXi 6.0 / 6.5 / 6.7"
);
global_var _centos_eol = make_array(
  # "7",    "2024-06-30",
  # "6",    "2020-11-30",
  "5",    "2017-03-31",
  "4",    "2012-02-29",  # https://lists.centos.org/pipermail/centos-announce/2012-February/018462.html
  "3",    "2010-10-31",  # https://wiki.centos.org/FAQ/General#head-fe8a0be91ee3e7dea812e8694491e1dde5b75e6d
  "2",    "2009-05-31"
);
global_var _fedora_eol = make_array(
  "27", "2018-11-30",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/ZSXRUH7JFXQNYP6JOAFTAUMSTLV6VMGO/
  "26", "2018-05-29",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/XGG7GYUJN3VDA6HX4KJNFSKSQCGF2FMW/
  "25", "2017-12-12",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/5VPF4YTQEXIGMR24VX5IRFYKONNNAEYW/
  "24", "2017-08-08",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/6PN47DOWEMLTUGJ2HCWAMXWFZ32HSTSH/
  "23", "2016-12-10",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/OHFCBTYXAO6NBH5BZZI3VIMIIL2ODFP5/
  "22", "2016-07-19",   # https://lists.fedoraproject.org/archives/list/announce@lists.fedoraproject.org/thread/4FBGGXFXRMU5GHT6OSSNOYVPMONZDWSD/
  "21", "2015-12-01",   # https://lists.fedoraproject.org/pipermail/devel/2015-November/216679.html
  "20", "2015-06-23",   # https://lists.fedoraproject.org/pipermail/announce/2015-May/003267.html
  "19", "2015-01-06",   # https://lists.fedoraproject.org/pipermail/announce/2015-January/003248.html
  "18", "2014-01-14",   # https://lists.fedoraproject.org/pipermail/announce/2014-January/003194.html
  "17", "2013-07-30",   # https://lists.fedoraproject.org/pipermail/announce/2013-July/003177.html
  "16", "2013-02-12",   # https://lists.fedoraproject.org/pipermail/announce/2013-February/003144.html
  "15", "2012-06-26",   # https://lists.fedoraproject.org/pipermail/announce/2012-May/003078.html
  "14", "2011-12-08",   # http://lists.fedoraproject.org/pipermail/announce/2011-November/003010.html
  "13", "2011-06-24",   # https://lists.fedoraproject.org/pipermail/announce/2011-June/002979.html
  "12", "2010-12-02",   # https://lists.fedoraproject.org/pipermail/announce/2010-December/002895.html
  "11", "2010-06-25",   # https://lists.fedoraproject.org/pipermail/announce/2010-June/002830.html
  "10", "2009-12-17",
  "9",  "2009-07-10",
  "8",  "2009-01-07",
  "7",  "2008-06-13",
  "6",  "2007-12-07",
  "5",  "2007-07-02",
  "4",  "2006-08-07",
  "3",  "2006-01-16",
  "2",  "2005-04-11",
  "1",  "2004-09-20"
);
global_var _freebsd_eol = make_array(
  "4.11", "2007-01-31",
  "5.3",  "2006-10-31",
  "5.4",  "2006-10-31",
  "5.5",  "2008-05-31",
  "6.0",  "2006-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "6.1",  "2008-05-31",
  "6.2",  "2008-05-31",
  "6.3",  "2010-01-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-October/005353.html
  "6.4",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "7.0",  "2009-04-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2009-April/005205.html
  "7.1",  "2011-02-28",   # http://lists.freebsd.org/pipermail/freebsd-security/2011-January/005771.html
  "7.2",  "2010-06-30",   # http://lists.freebsd.org/pipermail/freebsd-announce/2010-June/001325.html
  "7.3",  "2012-03-31",   # http://lists.freebsd.org/pipermail/freebsd-security/2012-March/006202.html
  "7.4",  "2012-02-28",
  "8.0",  "2010-11-30",   # http://lists.freebsd.org/pipermail/freebsd-security/2010-November/005713.html
  "8.1",  "2012-07-31",
  "8.2",  "2012-07-31",
  "8.3",  "2014-04-30",
  "8.4",  "2015-08-01",   # https://lists.freebsd.org/pipermail/freebsd-announce/2015-August/001664.html
  "9.0",  "2013-03-31",
  "9.1",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "9.2",  "2014-12-31",   # http://lists.freebsd.org/pipermail/freebsd-announce/2014-December/001615.html
  "9.3",  "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "10.0", "2015-03-02",   # http://lists.freebsd.org/pipermail/freebsd-announce/2015-March/001630.html
  "10.1", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "10.2", "2016-12-31",   # https://lists.freebsd.org/pipermail/freebsd-announce/2017-January/001779.html
  "10.3", "2018-04-30",
  "11.0", "2017-11-30",    # https://lists.freebsd.org/pipermail/freebsd-announce/2017-December/001816.html
  "11.1", "2018-09-30"
);
global_var _ubuntu_eol = make_array(
  "17.10", "2018-07-19",   # https://itsfoss.com/ubuntu-17-10-end-of-life/
  "17.04", "2018-01-13",   # https://lists.ubuntu.com/archives/ubuntu-announce/2018-January/000227.html
  "16.10", "2017-07-20",   # http://fridge.ubuntu.com/2017/07/20/ubuntu-16-10-yakkety-yak-end-of-life-reached-on-july-20-2017/
  "15.10", "2016-07-28",   # http://fridge.ubuntu.com/2016/07/07/ubuntu-15-10-wily-werewolf-reaches-end-of-life-on-july-28-2016/
  "15.04", "2016-02-04",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2016-February/003294.html
  "14.10", "2015-07-23",   # http://fridge.ubuntu.com/2015/07/03/ubuntu-14-10-utopic-unicorn-reaches-end-of-life-on-july-23-2015/
  "13.10", "2014-07-17",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-July/002598.html
  "13.04", "2014-01-27",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-January/002382.html
  "12.10", "2014-05-16",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2014-May/002515.html
  "12.04", "2017-04-30",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2017-April/003833.html
  "11.10", "2013-05-09",   # https://lists.ubuntu.com/archives/ubuntu-announce/2013-March/000167.html
  "11.04", "2012-10-28",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001882.html
  "10.10", "2012-04-10",   # https://lists.ubuntu.com/archives/ubuntu-announce/2012-April/000158.html
  "10.04", "2015-04-30",   # https://lists.ubuntu.com/archives/ubuntu-announce/2013-March/000169.html
  "9.10",  "2011-04-30",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-March/000142.html
  "9.04",  "2010-10-23",   # https://lists.ubuntu.com/archives/ubuntu-announce/2010-September/000137.html
  "8.10",  "2010-04-30",   # https://lists.ubuntu.com/archives/ubuntu-announce/2010-March/000130.html
  "8.04",  "2013-05-09",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-April/000144.html
  "7.10",  "2009-04-18",   # http://www.ubuntu.com/news/ubuntu-7.10-eol
  "7.04",  "2008-10-19",   # https://lists.ubuntu.com/archives/ubuntu-announce/2008-September/000113.html
  "6.10",  "2008-04-25",   # https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-March/000680.html
  "6.06",  "2011-06-01",   # https://lists.ubuntu.com/archives/ubuntu-announce/2011-June/000149.html
  "5.10",  "2007-04-13",
  "5.04",  "2006-10-31",
  "4.10",  "2006-04-30"
);
#https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/support/product-lifecycle-matrix.pdf
global_var _vmware_eol = make_array(
#  "ESXi 6.7", "2021-11-15",
#  "ESXi 6.5", "2021-11-15",
#  "ESXi 6.0", "2020-03-12",
  "ESXi 5.5", "2018-09-19",
  "ESXi 5.1", "2016-08-24",
  "ESXi 5.0", "2016-08-24",
  "ESXi 4.1", "2014-05-21",
  "ESXi 4.0", "2014-05-21",
  "ESXi 3.5", "2010-05-21",
  "ESX 5.0", "2016-08-24",
  "ESX 4.1", "2014-05-21",
  "ESX 4.0", "2014-05-21",
  "ESX 3.5", "2013-05-21",
  "ESX 3.0", "2011-12-10",
  "ESX 2.5", "2010-06-15",
  "ESX 2.1", "2010-06-15",
  "ESX 2.0", "2010-06-15"
);

