


# Instruction for Linux #

## Introduction ##

To compile sources you need linux tools such as gcc, svn, autoconf, automake, libtool, bison, yacc, flex, GTK+, GLib, libpcap.


## Details ##

At first you need to download Wireshark sources. You can get it by:
```
wget http://wiresharkdownloads.riverbed.com/wireshark/src/wireshark-1.6.0.tar.bz2
```

Next unpack downloaded file.
```
tar -xvjf wireshark-1.6.0.tar.bz2
```

Now get XMPP dissector sources.
```
svn checkout http://xmpp-dissector.googlecode.com/svn/trunk/ wireshark-1.6.0 --force
```

If you have all sources, patch all make files. It will allow you to compile XMPP dissector sources.
```
cd wireshark-1.6.0
patch -p0 -i wireshark_config.patch
```

Next run
```
./autogen.sh
./configure --prefix=/your-path/wireshark-bin
make && make install
```

If errors didn't occur, Wireshark is built correctly and you can use it by
```
/your-path/wireshark-bin/bin/wireshark
```

# Instruction for Windows #

## Introduction ##

To compile sources you need tools such as Visual C++ compiler, subversion client, Cygwin, Python interpreter, program to unpack tar.bz2 archive.


## Details ##

At first you should download and install the following tools:
  * Visual C++ 2010 Express - http://www.microsoft.com/visualstudio/en-us/products/2010-editions/visual-cpp-express
  * subversion client - http://www.sliksvn.com/en/download
  * patch tool - http://gnuwin32.sourceforge.net/downlinks/patch.php
  * Python - http://www.python.org/download/releases/2.7.2/
  * Cygwin - http://cygwin.com/setup.exe - during the installation from "Select Package" page choose the following packages: Archive/unzip, Devel/bison, Devel/flex, Interpreters/perl, Web/wget

Next download and unpack Wireshark's [sources](http://wiresharkdownloads.riverbed.com/wireshark/src/wireshark-1.6.1.tar.bz2).

Now download sources of XMPP dissector and patch required files. All commands must be call from command line.
```
cd wireshark-1.6.1
svn co http://xmpp-dissector.googlecode.com/svn/trunk/ . --force
patch -p0 -i wireshark_config.patch --binary
```

If command patch isn't recognized then
```
Path=%Path%;C:\Program Files\GnuWin32\bin #this is my path to the patch tool
patch -p0 -i wireshark_config.patch --binary
```

Next edit wireshark-1.6.1\config.nmake file. Uncomment 128th line. It should looks like:
```
# "Microsoft Visual C++ 2010 Express Edition"
# Visual C++ 10.0, _MSC_VER 1600, msvcr100.dll
MSVC_VARIANT=MSVC2010EE
```

Now you can compile sources
```
cd wireshark-1.6.1
C:\Program Files\Microsoft Visual Studio 10.0\VC\bin\vcvars32.bat
Nmake -f Makefile.nmake setup
Nmake -f Makefile.nmake all
```

If you get:
```
config.nmake(951) : fatal error U1050: Can't find C:\wireshark-win32-libs-1.6\vcredist_x86.exe. Have you downloaded it from Microsoft? See the developer's guide section "C-Runtime "Redistributable" files" for details how to get it
```
you should download this [file](http://www.microsoft.com/download/en/confirmation.aspx?id=5555) and copy it to the C:\wireshark-win32-libs-1.6 directory.

All ready for use binaries you can find in the wireshark-1.6.1\wireshark-gtk2 directory.