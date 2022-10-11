$Header: $

EAPI=3

inherit eutils

DESCRIPTION="Perl scripts to parse Windows registry files"
HOMEPAGE="http://regripper.wordpress.com/"
SRC_URI="http://regripper.googlecode.com/files/rrv${PV}.zip"
SRC_URI2="wget -q https://regripper.googlecode.com/files/rrv2.8.zip"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DEPEND="app-text/dos2unix
app-forensics/rrip-plugins"
RDEPEND="perl-gcpan/Parse-Win32Registry"

S="${WORKDIR}/${P/_/}"


src_prepare() {
    rm -rf plugins *.exe rr.pl *.dll
}

src_compile() {
    dos2unix *.pl
    epatch "${FILESDIR}"/plugins_folder.patch

    sed -i 's|c:\\perl\\bin\\perl.exe|/usr/bin/perl -w|g' rip.pl || die
}

src_install () {
    newbin rip.pl ${PN}
    rm rip.pl pb.pl
