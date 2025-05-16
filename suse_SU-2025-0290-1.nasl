#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0290-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214902);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2020-6923");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0290-1");

  script_name(english:"SUSE SLES12 Security Update : hplip (SUSE-SU-2025:0290-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2025:0290-1 advisory.

    This update for hplip fixes the following security issues:

    - CVE-2020-6923:  Fixed a memory buffer overflow in the HP Linux Imaging and Printing (HPLIP).
    (bsc#1234745)

    This update for hplip fixes the following issues:

    Update to hplip 3.24.4 (jsc#PED-5846)

    - Added support for new printers:
     * Digital Sender Flow 8500 fn2
     * HP Color LaserJet  Managed FlowMFP E786z
     * HP Color LaserJet E85055dn
     * HP Color LaserJet Enterprise 5700
     * HP Color LaserJet Enterprise 5700dn
     * HP Color LaserJet Enterprise 6700
     * HP Color LaserJet Enterprise 6700dn
     * HP Color LaserJet Enterprise 6701
     * HP Color LaserJet Enterprise 6701dn
     * HP Color LaserJet Enterprise Flow MFP 5800zf
     * HP Color LaserJet Enterprise Flow MFP 6800zf
     * HP Color LaserJet Enterprise Flow MFP 6800zfsw
     * HP Color LaserJet Enterprise Flow MFP 6800zfw+
     * HP Color LaserJet Enterprise Flow MFP 6801zfw+
     * HP Color LaserJet Enterprise Flow MFP M578c
     * HP Color LaserJet Enterprise Flow MFP M578z
     * HP Color LaserJet Enterprise Flow MFP X57945z
     * HP Color LaserJet Enterprise Flow MFP X57945zs
     * HP Color LaserJet Enterprise Flow MFP X58045z
     * HP Color LaserJet Enterprise Flow MFP X58045zs
     * HP Color LaserJet Enterprise Flow MFP X67755z+
     * HP Color LaserJet Enterprise Flow MFP X67755zs
     * HP Color LaserJet Enterprise Flow MFP X67765z+
     * HP Color LaserJet Enterprise Flow MFP X67765zs
     * HP Color LaserJet Enterprise Flow MFP X677z
     * HP Color LaserJet Enterprise Flow MFP X677z+
     * HP Color LaserJet Enterprise Flow MFP X677zs
     * HP Color LaserJet Enterprise M455dn
     * HP Color LaserJet Enterprise M554dn
     * HP Color LaserJet Enterprise M555dn
     * HP Color LaserJet Enterprise M555x
     * HP Color LaserJet Enterprise M751dn
     * HP Color LaserJet Enterprise M751n
     * HP Color LaserJet Enterprise MFP 5800
     * HP Color LaserJet Enterprise MFP 5800dn
     * HP Color LaserJet Enterprise MFP 5800f
     * HP Color LaserJet Enterprise MFP 6800
     * HP Color LaserJet Enterprise MFP 6800dn
     * HP Color LaserJet Enterprise MFP 6801
     * HP Color LaserJet Enterprise MFP 6801 zfsw
     * HP Color LaserJet Enterprise MFP M480f
     * HP Color LaserJet Enterprise MFP M578dn
     * HP Color LaserJet Enterprise MFP M578f
     * HP Color LaserJet Enterprise MFP X57945
     * HP Color LaserJet Enterprise MFP X57945dn
     * HP Color LaserJet Enterprise MFP X58045
     * HP Color LaserJet Enterprise MFP X58045dn
     * HP Color LaserJet Enterprise MFP X677
     * HP Color LaserJet Enterprise MFP X677 55 to 65ppm License
     * HP Color LaserJet Enterprise MFP X677 65ppm
     * HP Color LaserJet Enterprise MFP X67755dn
     * HP Color LaserJet Enterprise MFP X67765dn
     * HP Color LaserJet Enterprise MFP X677dn
     * HP Color LaserJet Enterprise MFP X677s
     * HP Color LaserJet Enterprise X55745
     * HP Color LaserJet Enterprise X55745dn
     * HP Color LaserJet Enterprise X654
     * HP Color LaserJet Enterprise X654 55 to 65ppm License
     * HP Color LaserJet Enterprise X654 65 PPM
     * HP Color LaserJet Enterprise X654 Down License
     * HP Color LaserJet Enterprise X65455dn
     * HP Color LaserJet Enterprise X65465dn
     * HP Color LaserJet Enterprise X654dn
     * HP Color LaserJet Flow MFP M776z
     * HP Color LaserJet Flow MFP M776zs
     * HP Color LaserJet M856dn
     * HP Color LaserJet M856x
     * HP Color LaserJet Managed E45028dn
     * HP Color LaserJet Managed E55040dn
     * HP Color LaserJet Managed E55040dw
     * HP Color LaserJet Managed E65150dn
     * HP Color LaserJet Managed E65160dn
     * HP Color LaserJet Managed E75245dn
     * HP Color LaserJet Managed Flow MFP E57540c
     * HP Color LaserJet Managed Flow MFP E67660z
     * HP Color LaserJet Managed Flow MFP E78323z
     * HP Color LaserJet Managed Flow MFP E78325dn CN
     * HP Color LaserJet Managed Flow MFP E78325z CN
     * HP Color LaserJet Managed Flow MFP E78325z Plus
     * HP Color LaserJet Managed Flow MFP E78330z CN
     * HP Color LaserJet Managed Flow MFP E78330z Plus
     * HP Color LaserJet Managed Flow MFP E78625z
     * HP Color LaserJet Managed Flow MFP E78630z
     * HP Color LaserJet Managed Flow MFP E78635z
     * HP Color LaserJet Managed Flow MFP E87740z
     * HP Color LaserJet Managed Flow MFP E87750z
     * HP Color LaserJet Managed Flow MFP E87760z
     * HP Color LaserJet Managed Flow MFP E87770z
     * HP Color LaserJet Managed Flow MFP E877z
     * HP Color LaserJet Managed MFP E47528f
     * HP Color LaserJet Managed MFP E57540dn
     * HP Color LaserJet Managed MFP E67650dh
     * HP Color LaserJet Managed MFP E77422a
     * HP Color LaserJet Managed MFP E77422a-dv-dn
     * HP Color LaserJet Managed MFP E77422dn
     * HP Color LaserJet Managed MFP E77422dv
     * HP Color LaserJet Managed MFP E77428dn
     * HP Color LaserJet Managed MFP E77428dn
     * HP Color LaserJet Managed MFP E78223a
     * HP Color LaserJet Managed MFP E78223dn
     * HP Color LaserJet Managed MFP E78223dv
     * HP Color LaserJet Managed MFP E78228dn
     * HP Color LaserJet Managed MFP E78228dn CN
     * HP Color LaserJet Managed MFP E78228dn Plus
     * HP Color LaserJet Managed MFP E78323dn
     * HP Color LaserJet Managed MFP E78325dn
     * HP Color LaserJet Managed MFP E78325z
     * HP Color LaserJet Managed MFP E78330dn
     * HP Color LaserJet Managed MFP E78330z
     * HP Color LaserJet Managed MFP E78523dn
     * HP Color LaserJet Managed MFP E78528dn
     * HP Color LaserJet Managed MFP E785dn
     * HP Color LaserJet Managed MFP E786 Core Printer
     * HP Color LaserJet Managed MFP E78625dn
     * HP Color LaserJet Managed MFP E78630dn
     * HP Color LaserJet Managed MFP E78635dn
     * HP Color LaserJet Managed MFP E786dn
     * HP Color LaserJet Managed MFP E87640 du
     * HP Color LaserJet Managed MFP E87640-50-60 dn-du-z
     * HP Color LaserJet Managed MFP E87650du
     * HP Color LaserJet Managed MFP E87660du
     * HP Color LaserJet Managed MFP E877 Core Printer
     * HP Color LaserJet Managed MFP E87740dn
     * HP Color LaserJet Managed MFP E87750dn
     * HP Color LaserJet Managed MFP E87760dn
     * HP Color LaserJet Managed MFP E87770dn
     * HP Color LaserJet Managed MFP E877dn
     * HP Color LaserJet MFP M776dn
     * HP Color LaserJet Mgd Flw MFPE78323z CN
     * HP Color LaserJet Mgd Flw MFPE78323Z Plus
     * HP Color LaserJet Mngd MFP E78223dn CN
     * HP Color LaserJet Mngd MFP E78223dn Plus
     * HP Color LaserJet Mngd MFP E78323dn CN
     * HP Color LaserJet Mngd MFP E78323dn Plus
     * HP Color LaserJet Mngd MFP E78330dn CN
     * HP Color LaserJet Mngd MFP E78330dn Plus
     * HP Color LaserJet Pro 4201cdne
     * HP Color LaserJet Pro 4201cdwe
     * HP Color LaserJet Pro 4201dne
     * HP Color LaserJet Pro 4201dwe
     * HP Color LaserJet Pro 4202dn
     * HP Color LaserJet Pro 4202dne
     * HP Color LaserJet Pro 4202dw
     * HP Color LaserJet Pro 4202dwe
     * HP Color LaserJet Pro 4203cdn
     * HP Color LaserJet Pro 4203cdw
     * HP Color LaserJet Pro 4203dn
     * HP Color LaserJet Pro 4203dw
     * HP Color LaserJet Pro M155a
     * HP Color LaserJet Pro M155nw
     * HP Color LaserJet Pro M156a
     * HP Color LaserJet Pro M156nw
     * HP Color LaserJet Pro M255dn
     * HP Color LaserJet Pro M255dw
     * HP Color LaserJet Pro M255nw
     * HP Color LaserJet Pro M256dn
     * HP Color LaserJet Pro M256dw
     * HP Color LaserJet Pro M256nw
     * HP Color LaserJet Pro M453cdn
     * HP Color LaserJet Pro M453cdw
     * HP Color LaserJet Pro M454cdn
     * HP Color LaserJet Pro M454cdw
     * HP Color LaserJet Pro M454dn
     * HP Color LaserJet Pro M454dw
     * HP Color LaserJet Pro M454nw
     * HP Color LaserJet Pro MFP 4301cdwe
     * HP Color LaserJet Pro MFP 4301cfdne
     * HP Color LaserJet Pro MFP 4301cfdwe
     * HP Color LaserJet Pro MFP 4301fdne
     * HP Color LaserJet Pro MFP 4301fdwe
     * HP Color LaserJet Pro MFP 4302cdwe
     * HP Color LaserJet Pro MFP 4302dwe
     * HP Color LaserJet Pro MFP 4302fdn
     * HP Color LaserJet Pro MFP 4302fdne
     * HP Color LaserJet Pro MFP 4302fdw
     * HP Color LaserJet Pro MFP 4302fdwe
     * HP Color LaserJet Pro MFP 4303cdw
     * HP Color LaserJet Pro MFP 4303cfdn
     * HP Color LaserJet Pro MFP 4303cfdw
     * HP Color LaserJet Pro MFP 4303dw
     * HP Color LaserJet Pro MFP 4303fdn
     * HP Color LaserJet Pro MFP 4303fdw
     * HP Color LaserJet Pro MFP M182n
     * HP Color LaserJet Pro MFP M182nw
     * HP Color LaserJet Pro MFP M183fw
     * HP Color LaserJet Pro MFP M184n
     * HP Color LaserJet Pro MFP M184nw
     * HP Color LaserJet Pro MFP M185fw
     * HP Color LaserJet Pro MFP M282nw
     * HP Color LaserJet Pro MFP M283cdw
     * HP Color LaserJet Pro MFP M283fdn
     * HP Color LaserJet Pro MFP M283fdw
     * HP Color LaserJet Pro MFP M284nw
     * HP Color LaserJet Pro MFP M285cdw
     * HP Color LaserJet Pro MFP M285fdn
     * HP Color LaserJet Pro MFP M285fdw
     * HP Color LaserJet Pro MFP M478fcdn
     * HP Color LaserJet Pro MFP M478fcdw
     * HP Color LaserJet Pro MFP M479dw
     * HP Color LaserJet Pro MFP M479fcdn
     * HP Color LaserJet Pro MFP M479fcdw
     * HP Color LaserJet Pro MFP M479fdn
     * HP Color LaserJet Pro MFP M479fdw
     * HP Color LaserJet Pro MFP M479fnw
     * HP DesignJet T1530 Postscript
     * HP DesignJet T1600 Postscript Printer
     * HP DesignJet T1600dr Postscript Printer
     * HP DesignJet T1708 PostScript
     * HP DesignJet T1708dr PostScript
     * HP DesignJet T2530 Postscript
     * HP DesignJet T2600 Postscript MFP
     * HP DesignJet T2600dr Postscript MFP
     * HP DesignJet T930 Postscript
     * HP DesignJet XL 3600 PS MFP
     * HP DesignJet Z6 24in
     * HP DesignJet Z6 44in
     * HP DesignJet Z6 Pro 64in
     * HP DesignJet Z6dr 44in
     * HP DesignJet Z9 24in
     * HP DesignJet Z9 44in
     * HP DesignJet Z9 Pro 64in
     * HP DesignJet Z9dr 44in
     * HP DeskJet 1200
     * HP DeskJet 2300 All-in-One
     * HP DeskJet 2700 All-in-One Printer series
     * HP DeskJet 2800 All-in-One Printer series
     * HP DeskJet 2800e All-in-One Printer series
     * HP DeskJet 4200 All-in-One Printer series
     * HP DeskJet 4200e All-in-One Printer series
     * HP DeskJet Ink Advantage 1200
     * HP DeskJet Ink Advantage 2300 All-in-One
     * HP DeskJet Ink Advantage 2700 All-in-One Printer series
     * HP DeskJet Ink Advantage 2800 All-in-One Printer series
     * HP DeskJet Ink Advantage 4100 All-in-One Printer series
     * HP DeskJet Ink Advantage 4200 All-in-One Printer series
     * HP DeskJet Ink Advantage Ultra 4800 All-in-One Printer series
     * HP DeskJet Ink Advantage Ultra 4900 All-in-One Printer series
     * HP DeskJet Plus 4100 All-in-One Printer series
     * HP DeskJet Plus 6000 series
     * HP DeskJet Plus 6400 series
     * HP ENVY 6000 series
     * HP Envy 6400 series
     * HP ENVY Inspire 7200e series
     * HP ENVY Inspire 7900e series
     * HP ENVY Pro 6400 series
     * HP Ink Tank 115
     * HP Ink Tank 310
     * HP Ink Tank Wireless 410
     * HP Lasejet  M211d
     * HP Laser NS 1020
     * HP Laser NS 1020n
     * HP Laser NS 1020w
     * HP Laser NS MFP 1005
     * HP Laser NS MFP 1005n
     * HP Laser NS MFP 1005w
     * HP LaserJet Enterprise Flow MFP M528c
     * HP LaserJet Enterprise Flow MFP M528z
     * HP LaserJet Enterprise Flow MFP M634h
     * HP LaserJet Enterprise Flow MFP M635z
     * HP LaserJet Enterprise Flow MFP M636z
     * HP LaserJet Enterprise M406dn
     * HP LaserJet Enterprise M407dn
     * HP LaserJet Enterprise M507dn
     * HP LaserJet Enterprise M507dng
     * HP LaserJet Enterprise M507n
     * HP LaserJet Enterprise M507x
     * HP LaserJet Enterprise M610dn
     * HP LaserJet Enterprise M611dn
     * HP LaserJet Enterprise M611x
     * HP LaserJet Enterprise M612dn
     * HP LaserJet Enterprise M612x
     * HP LaserJet Enterprise MFP M430f
     * HP LaserJet Enterprise MFP M431f
     * HP LaserJet Enterprise MFP M528dn
     * HP LaserJet Enterprise MFP M528f
     * HP LaserJet Enterprise MFP M634dn
     * HP LaserJet Enterprise MFP M634z
     * HP LaserJet Enterprise MFP M635fht
     * HP LaserJet Enterprise MFP M635h
     * HP LaserJet Enterprise MFP M636fh
     * HP LaserJet M109a
     * HP LaserJet M109w
     * HP LaserJet M109we
     * HP LaserJet M110a
     * HP LaserJet M110w
     * HP LaserJet M110we
     * HP LaserJet M111a
     * HP LaserJet M111w
     * HP LaserJet M111we
     * HP LaserJet M112a
     * HP LaserJet M112w
     * HP LaserJet M112we
     * HP Laserjet M207d
     * HP Laserjet M207dw
     * HP Laserjet M208d
     * HP Laserjet M208dw
     * HP Laserjet M209d
     * HP Laserjet M209dw
     * HP Laserjet M209dwe
     * HP Laserjet M210d
     * HP Laserjet M210dw
     * HP Laserjet M210dwe
     * HP Laserjet M211dw
     * HP Laserjet M212d
     * HP Laserjet M212dw
     * HP LaserJet M212dwe
     * HP LaserJet Managed E40040dn
     * HP LaserJet Managed E50145dn
     * HP LaserJet Managed E50145x
     * HP LaserJet Managed E60155dn
     * HP LaserJet Managed E60165dn
     * HP LaserJet Managed E60175dn
     * HP LaserJet Managed Flow MFP E52645c
     * HP LaserJet Managed Flow MFP E62665h
     * HP LaserJet Managed Flow MFP E62665z
     * HP LaserJet Managed Flow MFP E62675z
     * HP LaserJet Managed Flow MFP E72525-30-35 Printer
     * HP LaserJet Managed Flow MFP E73130z
     * HP LaserJet Managed Flow MFP E73135z
     * HP LaserJet Managed Flow MFP E73140z
     * HP LaserJet Managed Flow MFP E731z
     * HP LaserJet Managed Flow MFP E77822-28-30 Printer
     * HP LaserJet Managed Flow MFP E82540-50-60 Printer
     * HP LaserJet Managed Flow MFP E82650z
     * HP LaserJet Managed Flow MFP E82660z
     * HP LaserJet Managed Flow MFP E82670z
     * HP LaserJet Managed Flow MFP E826z
     * HP LaserJet Managed Flow MFP E87640-50-60 Printer
     * HP LaserJet Managed MFP E42540f
     * HP LaserJet Managed MFP E52645dn
     * HP LaserJet Managed MFP E62655dn
     * HP LaserJet Managed MFP E62665hs
     * HP LaserJet Managed MFP E72525-30-35 Printer
     * HP LaserJet Managed MFP E73025dn
     * HP LaserJet Managed MFP E73030dn
     * HP LaserJet Managed MFP E730dn
     * HP LaserJet Managed MFP E731 Core Printer
     * HP LaserJet Managed MFP E73130dn
     * HP LaserJet Managed MFP E73135dn
     * HP LaserJet Managed MFP E73140dn
     * HP LaserJet Managed MFP E731dn
     * HP LaserJet Managed MFP E77822-28-30 Printer
     * HP LaserJet Managed MFP E82540-50-60 dn-du-z
     * HP LaserJet Managed MFP E82540-50-60 Printer
     * HP LaserJet Managed MFP E82540du
     * HP LaserJet Managed MFP E82550du
     * HP LaserJet Managed MFP E82560du
     * HP LaserJet Managed MFP E826 Core Printer
     * HP LaserJet Managed MFP E82650dn
     * HP LaserJet Managed MFP E82660dn
     * HP LaserJet Managed MFP E82670dn
     * HP LaserJet Managed MFP E826dn
     * HP LaserJet Managed MFP E87640-50-60 Printer
     * HP LaserJet MFP E72425a
     * HP LaserJet MFP E72425a-dv-dn
     * HP LaserJet MFP E72425dn
     * HP LaserJet MFP E72425dv
     * HP LaserJet MFP E72430dn
     * HP LaserJet MFP E72430dn
     * HP LaserJet MFP M139a
     * HP LaserJet MFP M139w
     * HP LaserJet MFP M139we
     * HP LaserJet MFP M140a
     * HP LaserJet MFP M140w
     * HP LaserJet MFP M140we
     * HP LaserJet MFP M141a
     * HP LaserJet MFP M141w
     * HP LaserJet MFP M141we
     * HP LaserJet MFP M142a
     * HP LaserJet MFP M142w
     * HP LaserJet MFP M142we
     * HP LaserJet MFP M232d
     * HP LaserJet MFP M232dw
     * HP LaserJet MFP M232dwc
     * HP LaserJet MFP M232sdn
     * HP LaserJet MFP M232sdw
     * HP LaserJet MFP M233d
     * HP LaserJet MFP M233dw
     * HP LaserJet MFP M233sdn
     * HP LaserJet MFP M233sdw
     * HP LaserJet MFP M234dw
     * HP LaserJet MFP M234dwe
     * HP LaserJet MFP M234sdn
     * HP LaserJet MFP M234sdne
     * HP LaserJet MFP M234sdw
     * HP LaserJet MFP M234sdwe
     * HP LaserJet MFP M235d
     * HP LaserJet MFP M235dw
     * HP LaserJet MFP M235dwe
     * HP LaserJet MFP M235sdn
     * HP LaserJet MFP M235sdne
     * HP LaserJet MFP M235sdw
     * HP LaserJet MFP M235sdwe
     * HP LaserJet MFP M236d
     * HP LaserJet MFP M236dw
     * HP LaserJet MFP M236sdn
     * HP LaserJet MFP M236sdw
     * HP LaserJet MFP M237d
     * HP LaserJet MFP M237dw
     * HP LaserJet MFP M237dwe
     * HP LaserJet MFP M237sdn
     * HP LaserJet MFP M237sdne
     * HP LaserJet MFP M237sdw
     * HP LaserJet MFP M237sdwe
     * HP LaserJet Pro 3001dn
     * HP LaserJet Pro 3001dne
     * HP LaserJet Pro 3001dw
     * HP LaserJet Pro 3001dwe
     * HP LaserJet Pro 3002dn
     * HP LaserJet Pro 3002dne
     * HP LaserJet Pro 3002dw
     * HP LaserJet Pro 3002dwe
     * HP LaserJet Pro 3003dn
     * HP LaserJet Pro 3003dw
     * HP LaserJet Pro 3004dn
     * HP LaserJet Pro 3004dw
     * HP LaserJet Pro 4001d
     * HP LaserJet Pro 4001de
     * HP LaserJet Pro 4001dn
     * HP LaserJet Pro 4001dne
     * HP LaserJet Pro 4001dw
     * HP LaserJet Pro 4001dwe
     * HP LaserJet Pro 4001n
     * HP LaserJet Pro 4001ne
     * HP LaserJet Pro 4002d
     * HP LaserJet Pro 4002de
     * HP LaserJet Pro 4002dn
     * HP LaserJet Pro 4002dne
     * HP LaserJet Pro 4002dw
     * HP LaserJet Pro 4002dwe
     * HP LaserJet Pro 4002n
     * HP LaserJet Pro 4002ne
     * HP LaserJet Pro 4003d
     * HP LaserJet Pro 4003dn
     * HP LaserJet Pro 4003dw
     * HP LaserJet Pro 4003n
     * HP LaserJet Pro 4004d
     * HP LaserJet Pro 4004dn
     * HP LaserJet Pro 4004dw
     * HP LaserJet Pro M118dw
     * HP LaserJet Pro M118dw
     * HP LaserJet Pro M119dw
     * HP LaserJet Pro M119dw
     * HP LaserJet Pro M304a
     * HP LaserJet Pro M305d
     * HP LaserJet Pro M305dn
     * HP LaserJet Pro M305dw
     * HP LaserJet Pro M404c1
     * HP LaserJet Pro M404c2
     * HP LaserJet Pro M404c3
     * HP LaserJet Pro M404c4
     * HP LaserJet Pro M404d
     * HP LaserJet Pro M404dn
     * HP LaserJet Pro M404dw
     * HP LaserJet Pro M404m
     * HP LaserJet Pro M404n
     * HP LaserJet Pro M405d
     * HP LaserJet Pro M405dn
     * HP LaserJet Pro M405dw
     * HP LaserJet Pro M405n
     * HP LaserJet Pro MFP 3101fdn
     * HP LaserJet Pro MFP 3101fdne
     * HP LaserJet Pro MFP 3101fdw
     * HP LaserJet Pro MFP 3101fdwe
     * HP LaserJet Pro MFP 3102fdn
     * HP LaserJet Pro MFP 3102fdne
     * HP LaserJet Pro MFP 3102fdw
     * HP LaserJet Pro MFP 3102fdwe
     * HP LaserJet Pro MFP 3103fdn
     * HP LaserJet Pro MFP 3103fdw
     * HP LaserJet Pro MFP 3104fdn
     * HP LaserJet Pro MFP 3104fdw
     * HP LaserJet Pro MFP 4101dw
     * HP LaserJet Pro MFP 4101dwe
     * HP LaserJet Pro MFP 4101fdn
     * HP LaserJet Pro MFP 4101fdne
     * HP LaserJet Pro MFP 4101fdw
     * HP LaserJet Pro MFP 4101fdwe
     * HP LaserJet Pro MFP 4102dw
     * HP LaserJet Pro MFP 4102dwe
     * HP LaserJet Pro MFP 4102fdn
     * HP LaserJet Pro MFP 4102fdne
     * HP LaserJet Pro MFP 4102fdw
     * HP LaserJet Pro MFP 4102fdwe
     * HP LaserJet Pro MFP 4102fnw
     * HP LaserJet Pro MFP 4102fnwe
     * HP LaserJet Pro MFP 4103dn
     * HP LaserJet Pro MFP 4103dw
     * HP LaserJet Pro MFP 4103fdn
     * HP LaserJet Pro MFP 4103fdw
     * HP LaserJet Pro MFP 4104dw
     * HP LaserJet Pro MFP 4104fdn
     * HP LaserJet Pro MFP 4104fdw
     * HP LaserJet Pro MFP M148dw
     * HP LaserJet Pro MFP M148dw
     * HP LaserJet Pro MFP M148fdw
     * HP LaserJet Pro MFP M148fdw
     * HP LaserJet Pro MFP M149dw
     * HP LaserJet Pro MFP M149dw
     * HP LaserJet Pro MFP M149fdw
     * HP LaserJet Pro MFP M149fdw
     * HP LaserJet Pro MFP M329dn
     * HP LaserJet Pro MFP M329dw
     * HP LaserJet Pro MFP M428c1
     * HP LaserJet Pro MFP M428c2
     * HP LaserJet Pro MFP M428c3
     * HP LaserJet Pro MFP M428c4
     * HP LaserJet Pro MFP M428dw
     * HP LaserJet Pro MFP M428fdn
     * HP LaserJet Pro MFP M428fdw
     * HP LaserJet Pro MFP M428m
     * HP LaserJet Pro MFP M429dw
     * HP LaserJet Pro MFP M429fdn
     * HP LaserJet Pro MFP M429fdw
     * HP LaserJet Pro P1106 plus
     * HP LaserJet Pro P1108 plus
     * HP LaserJet Tank 1020
     * HP LaserJet Tank 1020nw
     * HP LaserJet Tank 1020w
     * HP LaserJet Tank 1502a
     * HP LaserJet Tank 1502w
     * HP LaserJet Tank 1504w
     * HP LaserJet Tank 2502dn
     * HP LaserJet Tank 2502dw
     * HP LaserJet Tank 2503dw
     * HP LaserJet Tank 2504dw
     * HP LaserJet Tank 2506d
     * HP LaserJet Tank 2506dn
     * HP LaserJet Tank 2506dw
     * HP LaserJet Tank MFP 1005
     * HP LaserJet Tank MFP 1005nw
     * HP LaserJet Tank MFP 1005w
     * HP LaserJet Tank MFP 1602a
     * HP LaserJet Tank MFP 1602w
     * HP LaserJet Tank MFP 1604w
     * HP LaserJet Tank MFP 2602dn
     * HP LaserJet Tank MFP 2602dw
     * HP LaserJet Tank MFP 2602sdn
     * HP LaserJet Tank MFP 2602sdw
     * HP LaserJet Tank MFP 2603dw
     * HP LaserJet Tank MFP 2603sdw
     * HP LaserJet Tank MFP 2604dw
     * HP LaserJet Tank MFP 2604sdw
     * HP LaserJet Tank MFP 2605sdw
     * HP LaserJet Tank MFP 2606dc
     * HP LaserJet Tank MFP 2606dn
     * HP LaserJet Tank MFP 2606dw
     * HP LaserJet Tank MFP 2606sdn
     * HP LaserJet Tank MFP 2606sdw
     * HP Neverstop Laser 1000a
     * HP Neverstop Laser 1000n
     * HP Neverstop Laser 1000w
     * HP Neverstop Laser 1001nw
     * HP Neverstop Laser MFP 1200a
     * HP Neverstop Laser MFP 1200n
     * HP Neverstop Laser MFP 1200nw
     * HP Neverstop Laser MFP 1200w
     * HP Neverstop Laser MFP 1201n
     * HP Neverstop Laser MFP 1202nw
     * HP OfficeJet 8010 All  * in  * One Printer series
     * HP OfficeJet 8020 All  * in  * One Printer Series
     * HP OfficeJet 8120 All-in-One series
     * HP OfficeJet 8130 All-in-One series
     * HP OfficeJet All-in-One 9010
     * HP OfficeJet Pro 8020 All  * in  * One Printer series
     * HP OfficeJet Pro 8030 All  * in  * One Printer series
     * HP OfficeJet Pro 8120 All-in-One series
     * HP OfficeJet Pro 8130 All-in-One series
     * HP OfficeJet Pro 9110b series
     * HP OfficeJet Pro 9120b series
     * HP OfficeJet Pro 9130b series
     * HP OfficeJet Pro 9720 Series
     * HP OfficeJet Pro 9730 Series
     * HP OfficeJet Pro All-in-One 9010
     * HP OfficeJet Pro All-in-One 9020
     * HP PageWide 755dn
     * HP PageWide 755dn
     * HP PageWide MFP 774dn
     * HP PageWide MFP 774dn
     * HP PageWide MFP 774dns
     * HP PageWide MFP 774dns
     * HP PageWide MFP 779dn
     * HP PageWide MFP 779dn
     * HP PageWide MFP 779dns
     * HP PageWide MFP 779dns
     * HP PageWide XL 3900PS MFP
     * HP PageWide XL 3920 MFP
     * HP PageWide XL 3920 MFP
     * HP PageWide XL 4100 MFP
     * HP PageWide XL 4100 Printer
     * HP PageWide XL 4200 Multifunction Printer
     * HP PageWide XL 4200 Multifunction Printer
     * HP PageWide XL 4200 Printer
     * HP PageWide XL 4200 Printer
     * HP PageWide XL 4600 Printer
     * HP PageWide XL 4600PS MFP
     * HP PageWide XL 4700 Multifunction Printer
     * HP PageWide XL 4700 Multifunction Printer
     * HP PageWide XL 4700 Printer
     * HP PageWide XL 4700 Printer
     * HP PageWide XL 5200 Multifunction Printer
     * HP PageWide XL 5200 Multifunction Printer
     * HP PageWide XL 5200 Printer
     * HP PageWide XL 5200 Printer
     * HP PageWide XL 8200 Printer
     * HP PageWide XL 8200 Printer
     * HP PageWide XL Pro 5200 PS MFP series
     * HP PageWide XL Pro 8200 PS MFP series
     * HP Scanjet Enterprise 7500 Flatbed Scanner
     * HP Scanjet Enterprise 7500 Flatbed Scanner
     * HP ScanJet Enterprise Flow 5000 s5
     * HP ScanJet Enterprise Flow N6600 fnw1
     * HP ScanJet Enterprise Flow N7000 snw1
     * HP Scanjet Pro 2000 S1
     * HP ScanJet Pro 2000 s2
     * HP Scanjet Pro 2500 f1
     * HP ScanJet Pro 2600 f1
     * HP ScanJet Pro 3000 s4
     * HP ScanJet Pro 3600 f1
     * HP ScanJet Pro N4000 snw1
     * HP ScanJet Pro N4600 fnw1
     * HP Smart Tank 210-220 series
     * HP Smart Tank 350
     * HP Smart Tank 500 series
     * HP Smart Tank 500 series
     * HP Smart Tank 510
     * HP Smart Tank 5100 series
     * HP Smart Tank 520_540 series
     * HP Smart Tank 530 series
     * HP Smart Tank 530 series
     * HP Smart Tank 580-590 series
     * HP Smart Tank 610
     * HP Smart Tank 750
     * HP Smart Tank 7600
     * HP Smart Tank 790
     * HP Smart Tank Plus 550
     * HP Smart Tank Plus 570 series
     * HP Smart Tank Plus 570 series
     * HP Smart Tank Plus 6000
     * HP Smart Tank Plus 650
     * HP Smart Tank Plus 660-670
     * HP Smart Tank Plus 7000
     * HP Smart Tank Plus 710-720
     * HP Smart Tank Wireless 450
     * HP Tango
     * HP Tango X
     * ScanJet 5000
     * ScanJet 7500
     * Scanjet Ent flow 7000s3
     * Scanjet Ent. Flow N9120 fn2
     * Scanjet Pro 3000s3
     * Scanjet Pro 3500f1
     * Scanjet Pro 4500fn1

    - Bug fixes:
      * hpmud: sanitize printer serial number (bsc#1209401, lp#2012262)

    - hppsfilter: booklet printing: change insecure fixed /tmp file paths (bsc#1214399)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234745");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020238.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7055a40a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6923");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6923");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-udev-rules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'hplip-3.24.4-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'hplip-devel-3.24.4-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'hplip-hpijs-3.24.4-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'hplip-sane-3.24.4-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'hplip-udev-rules-3.24.4-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'hplip-3.24.4-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'hplip-devel-3.24.4-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'hplip-hpijs-3.24.4-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'hplip-sane-3.24.4-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'hplip-udev-rules-3.24.4-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hplip / hplip-devel / hplip-hpijs / hplip-sane / hplip-udev-rules');
}
