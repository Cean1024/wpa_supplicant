ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif

# Include directories for CVS version
CFLAGS += -I. -I../utils -I../hostapd

ALL=wpa_supplicant wpa_passphrase wpa_cli dynamic_eap_methods

all: verify_config $(ALL)

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building wpa_supplicant requires a configuration file'; \
		echo '(.config). See README for more instructions. You can'; \
		echo 'run "cp defconfig .config" to create an example'; \
		echo 'configuration.'; \
		exit 1; \
	fi

mkconfig:
	@if [ -e .config ]; then \
		echo '.config exists - did not replace it'; \
		exit 1; \
	fi
	echo CONFIG_DRIVER_HOSTAP=y >> .config
	echo CONFIG_DRIVER_WEXT=y >> .config
	echo CONFIG_WIRELESS_EXTENSION=y >> .config

install: all
	mkdir -p $(DESTDIR)/usr/local/sbin/
	for i in $(ALL); do cp $$i $(DESTDIR)/usr/local/sbin/$$i; done

OBJS = config.o \
	common.o md5.o \
	rc4.o sha1.o
OBJS_p = wpa_passphrase.o sha1.o md5.o
OBJS_c = wpa_cli.o wpa_ctrl.o

-include .config

ifndef CONFIG_OS
ifdef CONFIG_NATIVE_WINDOWS
CONFIG_OS=win32
else
CONFIG_OS=unix
endif
endif

OBJS += os_$(CONFIG_OS).o
OBJS_p += os_$(CONFIG_OS).o
OBJS_c += os_$(CONFIG_OS).o

ifndef CONFIG_ELOOP
CONFIG_ELOOP=eloop
endif
OBJS += $(CONFIG_ELOOP).o


ifdef CONFIG_EAPOL_TEST
CFLAGS += -Werror -DEAPOL_TEST
endif

ifndef CONFIG_BACKEND
CONFIG_BACKEND=file
endif

ifeq ($(CONFIG_BACKEND), file)
OBJS += config_file.o base64.o
CFLAGS += -DCONFIG_BACKEND_FILE
endif

ifeq ($(CONFIG_BACKEND), winreg)
OBJS += config_winreg.o
endif

ifeq ($(CONFIG_BACKEND), none)
OBJS += config_none.o
endif

ifdef CONFIG_DRIVER_HOSTAP
CFLAGS += -DCONFIG_DRIVER_HOSTAP
OBJS_d += driver_hostap.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_WEXT
CFLAGS += -DCONFIG_DRIVER_WEXT
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_PRISM54
CFLAGS += -DCONFIG_DRIVER_PRISM54
OBJS_d += driver_prism54.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_HERMES
CFLAGS += -DCONFIG_DRIVER_HERMES
OBJS_d += driver_hermes.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_MADWIFI
CFLAGS += -DCONFIG_DRIVER_MADWIFI
OBJS_d += driver_madwifi.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_ATMEL
CFLAGS += -DCONFIG_DRIVER_ATMEL
OBJS_d += driver_atmel.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_NDISWRAPPER
CFLAGS += -DCONFIG_DRIVER_NDISWRAPPER
OBJS_d += driver_ndiswrapper.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_BROADCOM
CFLAGS += -DCONFIG_DRIVER_BROADCOM
OBJS_d += driver_broadcom.o
endif

ifdef CONFIG_DRIVER_IPW
CFLAGS += -DCONFIG_DRIVER_IPW
OBJS_d += driver_ipw.o
CONFIG_WIRELESS_EXTENSION=y
endif

ifdef CONFIG_DRIVER_BSD
CFLAGS += -DCONFIG_DRIVER_BSD
OBJS_d += driver_bsd.o
ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=freebsd
endif
endif

ifdef CONFIG_DRIVER_NDIS
CFLAGS += -DCONFIG_DRIVER_NDIS
OBJS_d += driver_ndis.o driver_ndis_.o
ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=pcap
endif
CONFIG_WINPCAP=y
endif

ifdef CONFIG_DRIVER_WIRED
CFLAGS += -DCONFIG_DRIVER_WIRED
OBJS_d += driver_wired.o
endif

ifdef CONFIG_DRIVER_TEST
CFLAGS += -DCONFIG_DRIVER_TEST
OBJS_d += driver_test.o
endif

ifndef CONFIG_L2_PACKET
CONFIG_L2_PACKET=linux
endif

OBJS += l2_packet_$(CONFIG_L2_PACKET).o

ifeq ($(CONFIG_L2_PACKET), pcap)
ifdef CONFIG_WINPCAP
CFLAGS += -DCONFIG_WINPCAP
LIBS += -lwpcap -lpacket
LIBS_w += -lwpcap
else
LIBS += -ldnet -lpcap
endif
endif

ifeq ($(CONFIG_L2_PACKET), winpcap)
LIBS += -lwpcap -lpacket
LIBS_w += -lwpcap
endif

ifeq ($(CONFIG_L2_PACKET), freebsd)
LIBS += -lpcap
endif

ifdef CONFIG_EAP_TLS
# EAP-TLS
ifeq ($(CONFIG_EAP_TLS), dyn)
CFLAGS += -DEAP_TLS_DYNAMIC
EAPDYN += eap_tls.so
else
CFLAGS += -DEAP_TLS
OBJS += eap_tls.o
endif
TLS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_PEAP
# EAP-PEAP
ifeq ($(CONFIG_EAP_PEAP), dyn)
CFLAGS += -DEAP_PEAP_DYNAMIC
EAPDYN += eap_peap.so
else
CFLAGS += -DEAP_PEAP
OBJS += eap_peap.o
endif
TLS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
CONFIG_EAP_TLV=y
endif

ifdef CONFIG_EAP_TTLS
# EAP-TTLS
ifeq ($(CONFIG_EAP_TTLS), dyn)
CFLAGS += -DEAP_TTLS_DYNAMIC
EAPDYN += eap_ttls.so
else
CFLAGS += -DEAP_TTLS
OBJS += eap_ttls.o
endif
MS_FUNCS=y
TLS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_MD5
# EAP-MD5
ifeq ($(CONFIG_EAP_MD5), dyn)
CFLAGS += -DEAP_MD5_DYNAMIC
EAPDYN += eap_md5.so
else
CFLAGS += -DEAP_MD5
OBJS += eap_md5.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

# backwards compatibility for old spelling
ifdef CONFIG_MSCHAPV2
ifndef CONFIG_EAP_MSCHAPV2
CONFIG_EAP_MSCHAPV2=y
endif
endif

ifdef CONFIG_EAP_MSCHAPV2
# EAP-MSCHAPv2
ifeq ($(CONFIG_EAP_MSCHAPV2), dyn)
CFLAGS += -DEAP_MSCHAPv2_DYNAMIC
EAPDYN += eap_mschapv2.so
else
CFLAGS += -DEAP_MSCHAPv2
OBJS += eap_mschapv2.o
endif
MS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_GTC
# EAP-GTC
ifeq ($(CONFIG_EAP_GTC), dyn)
CFLAGS += -DEAP_GTC_DYNAMIC
EAPDYN += eap_gtc.so
else
CFLAGS += -DEAP_GTC
OBJS += eap_gtc.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_OTP
# EAP-OTP
ifeq ($(CONFIG_EAP_OTP), dyn)
CFLAGS += -DEAP_OTP_DYNAMIC
EAPDYN += eap_otp.so
else
CFLAGS += -DEAP_OTP
OBJS += eap_otp.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_SIM
# EAP-SIM
ifeq ($(CONFIG_EAP_SIM), dyn)
CFLAGS += -DEAP_SIM_DYNAMIC
EAPDYN += eap_sim.so
else
CFLAGS += -DEAP_SIM
OBJS += eap_sim.o
endif
CONFIG_IEEE8021X_EAPOL=y
CONFIG_EAP_SIM_COMMON=y
endif

ifdef CONFIG_EAP_LEAP
# EAP-LEAP
ifeq ($(CONFIG_EAP_LEAP), dyn)
CFLAGS += -DEAP_LEAP_DYNAMIC
EAPDYN += eap_leap.so
else
CFLAGS += -DEAP_LEAP
OBJS += eap_leap.o
endif
MS_FUNCS=y
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_PSK
# EAP-PSK
ifeq ($(CONFIG_EAP_PSK), dyn)
CFLAGS += -DEAP_PSK_DYNAMIC
EAPDYN += eap_psk.so
else
CFLAGS += -DEAP_PSK
OBJS += eap_psk.o eap_psk_common.o
endif
CONFIG_IEEE8021X_EAPOL=y
NEED_AES=y
endif

ifdef CONFIG_EAP_AKA
# EAP-AKA
ifeq ($(CONFIG_EAP_AKA), dyn)
CFLAGS += -DEAP_AKA_DYNAMIC
EAPDYN += eap_aka.so
else
CFLAGS += -DEAP_AKA
OBJS += eap_aka.o
endif
CONFIG_IEEE8021X_EAPOL=y
CONFIG_EAP_SIM_COMMON=y
endif

ifdef CONFIG_EAP_SIM_COMMON
OBJS += eap_sim_common.o
NEED_AES=y
endif

ifdef CONFIG_EAP_TLV
# EAP-TLV
CFLAGS += -DEAP_TLV
OBJS += eap_tlv.o
endif

ifdef CONFIG_EAP_FAST
# EAP-FAST
ifeq ($(CONFIG_EAP_FAST), dyn)
CFLAGS += -DEAP_FAST_DYNAMIC
EAPDYN += eap_fast.so
else
CFLAGS += -DEAP_FAST
OBJS += eap_fast.o
endif
TLS_FUNCS=y
endif

ifdef CONFIG_EAP_PAX
# EAP-PAX
ifeq ($(CONFIG_EAP_PAX), dyn)
CFLAGS += -DEAP_PAX_DYNAMIC
EAPDYN += eap_pax.so
else
CFLAGS += -DEAP_PAX
OBJS += eap_pax.o eap_pax_common.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_SAKE
# EAP-SAKE
ifeq ($(CONFIG_EAP_SAKE), dyn)
CFLAGS += -DEAP_SAKE_DYNAMIC
EAPDYN += eap_sake.so
else
CFLAGS += -DEAP_SAKE
OBJS += eap_sake.o eap_sake_common.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_EAP_VENDOR_TEST
ifeq ($(CONFIG_EAP_VENDOR_TEST), dyn)
CFLAGS += -DEAP_VENDOR_TEST_DYNAMIC
EAPDYN += eap_vendor_test.so
else
CFLAGS += -DEAP_VENDOR_TEST
OBJS += eap_vendor_test.o
endif
CONFIG_IEEE8021X_EAPOL=y
endif

ifdef CONFIG_IEEE8021X_EAPOL
# IEEE 802.1X/EAPOL state machines (e.g., for RADIUS authentication)
CFLAGS += -DIEEE8021X_EAPOL
OBJS += eapol_sm.o eap.o eap_methods.o
ifdef CONFIG_DYNAMIC_EAP_METHODS
CFLAGS += -DCONFIG_DYNAMIC_EAP_METHODS
LIBS += -ldl -rdynamic
endif
endif

ifdef CONFIG_PCSC
# PC/SC interface for smartcards (USIM, GSM SIM)
CFLAGS += -DPCSC_FUNCS -I/usr/include/PCSC
OBJS += pcsc_funcs.o
# -lpthread may not be needed depending on how pcsc-lite was configured
ifdef CONFIG_NATIVE_WINDOWS
#Once MinGW gets support for WinScard, -lwinscard could be used instead of the
#dynamic symbol loading that is now used in pcsc_funcs.c
#LIBS += -lwinscard
else
LIBS += -lpcsclite -lpthread
endif
endif

ifndef CONFIG_TLS
CONFIG_TLS=openssl
endif

ifdef TLS_FUNCS
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, EAP_TTLS, and EAP_FAST)
CFLAGS += -DEAP_TLS_FUNCS
OBJS += eap_tls_common.o
ifeq ($(CONFIG_TLS), openssl)
CFLAGS += -DEAP_TLS_OPENSSL
OBJS += tls_openssl.o
LIBS += -lssl -lcrypto
LIBS_p += -lcrypto
endif
ifeq ($(CONFIG_TLS), gnutls)
OBJS += tls_gnutls.o
LIBS += -lgnutls -lgcrypt -lgpg-error
LIBS_p += -lgcrypt
ifdef CONFIG_GNUTLS_EXTRA
CFLAGS += -DCONFIG_GNUTLS_EXTRA
LIBS += -lgnutls-extra
endif
endif
ifeq ($(CONFIG_TLS), schannel)
OBJS += tls_schannel.o
# Using OpenSSL for crypto at the moment; to be replaced
CFLAGS += -DEAP_TLS_OPENSSL
LIBS += -lcrypto
LIBS_p += -lcrypto
endif
ifeq ($(CONFIG_TLS), none)
OBJS += tls_none.o
CFLAGS += -DEAP_TLS_NONE
endif
ifdef CONFIG_SMARTCARD
ifndef CONFIG_NATIVE_WINDOWS
ifneq ($(CONFIG_L2_PACKET), freebsd)
LIBS += -ldl
endif
endif
endif
NEED_CRYPTO=y
else
OBJS += tls_none.o
endif

ifdef CONFIG_PKCS12
CFLAGS += -DPKCS12_FUNCS
endif

ifdef CONFIG_SMARTCARD
CFLAGS += -DCONFIG_SMARTCARD
endif

ifdef MS_FUNCS
OBJS += ms_funcs.o
NEED_CRYPTO=y
endif

ifdef NEED_CRYPTO
ifndef TLS_FUNCS
ifeq ($(CONFIG_TLS), openssl)
LIBS += -lcrypto
LIBS_p += -lcrypto
endif
ifeq ($(CONFIG_TLS), gnutls)
LIBS += -lgcrypt
LIBS_p += -lgcrypt
endif
ifeq ($(CONFIG_TLS), schannel)
# Using OpenSSL for crypto at the moment; to be replaced
LIBS += -lcrypto
LIBS_p += -lcrypto
endif
endif
ifeq ($(CONFIG_TLS), openssl)
OBJS += crypto.o
OBJS_p += crypto.o
endif
ifeq ($(CONFIG_TLS), gnutls)
OBJS += crypto_gnutls.o
OBJS_p += crypto_gnutls.o
endif
ifeq ($(CONFIG_TLS), schannel)
# Using OpenSSL for crypto at the moment; to be replaced
OBJS += crypto.o
OBJS_p += crypto.o
endif
ifeq ($(CONFIG_TLS), none)
OBJS += crypto_none.o
OBJS_p += crypto_none.o
endif
endif

ifdef CONFIG_WIRELESS_EXTENSION
CFLAGS += -DCONFIG_WIRELESS_EXTENSION
OBJS_d += driver_wext.o
endif

ifdef CONFIG_CTRL_IFACE
ifeq ($(CONFIG_CTRL_IFACE), y)
ifdef CONFIG_NATIVE_WINDOWS
CONFIG_CTRL_IFACE=udp
else
CONFIG_CTRL_IFACE=unix
endif
endif
CFLAGS += -DCONFIG_CTRL_IFACE
ifeq ($(CONFIG_CTRL_IFACE), udp)
CFLAGS += -DCONFIG_CTRL_IFACE_UDP
endif
OBJS += ctrl_iface.o ctrl_iface_$(CONFIG_CTRL_IFACE).o
endif

ifdef CONFIG_CTRL_IFACE_DBUS
CFLAGS += -DCONFIG_CTRL_IFACE_DBUS
OBJS += ctrl_iface_dbus.o
LIBS += `pkg-config --libs dbus-1`
CFLAGS += `pkg-config --cflags dbus-1`
endif

ifdef CONFIG_READLINE
CFLAGS += -DCONFIG_READLINE
LIBS_c += -lncurses -lreadline
endif

ifdef CONFIG_NATIVE_WINDOWS
CFLAGS += -DCONFIG_NATIVE_WINDOWS
LIBS += -lws2_32 -lgdi32 -lcrypt32
LIBS_c += -lws2_32
LIBS_p += -lws2_32
endif

ifdef CONFIG_NO_STDOUT_DEBUG
CFLAGS += -DCONFIG_NO_STDOUT_DEBUG
endif

ifdef CONFIG_IPV6
# for eapol_test only
CFLAGS += -DCONFIG_IPV6
endif

ifdef CONFIG_STAKEY
CFLAGS += -DCONFIG_STAKEY
endif

ifndef CONFIG_NO_WPA
OBJS += wpa.o preauth.o pmksa_cache.o
NEED_AES=y
else
CFLAGS += -DCONFIG_NO_WPA -DCONFIG_NO_WPA2
endif

ifdef CONFIG_NO_WPA2
CFLAGS += -DCONFIG_NO_WPA2
endif

ifdef CONFIG_NO_AES_EXTRAS
CFLAGS += -DCONFIG_NO_AES_WRAP
CFLAGS += -DCONFIG_NO_AES_CTR -DCONFIG_NO_AES_OMAC1
CFLAGS += -DCONFIG_NO_AES_EAX -DCONFIG_NO_AES_CBC
endif

ifdef NEED_AES
OBJS += aes_wrap.o
endif

ifndef CONFIG_MAIN
CONFIG_MAIN=main
endif

OBJS += wpa_supplicant.o events.o
OBJS_t := $(OBJS) eapol_test.o radius.o radius_client.o
OBJS_t2 := $(OBJS) preauth_test.o
OBJS += $(CONFIG_MAIN).o drivers.o $(OBJS_d)

ifdef CONFIG_NDIS_EVENTS_INTEGRATED
CFLAGS += -DCONFIG_NDIS_EVENTS_INTEGRATED
OBJS += ndis_events.o
EXTRALIBS += -loleaut32 -lole32 -luuid
ifdef PLATFORMSDKLIB
EXTRALIBS += $(PLATFORMSDKLIB)/WbemUuid.Lib
else
EXTRALIBS += WbemUuid.Lib
endif
endif

ifndef LDO
LDO=$(CC)
endif

dynamic_eap_methods: $(EAPDYN)

wpa_supplicant: .config $(OBJS)
	$(LDO) $(LDFLAGS) -o wpa_supplicant $(OBJS) $(LIBS) $(EXTRALIBS)

eapol_test: .config $(OBJS_t)
	$(LDO) $(LDFLAGS) -o eapol_test $(OBJS_t) $(LIBS)

preauth_test: .config $(OBJS_t2) 
	$(LDO) $(LDFLAGS) -o preauth_test $(OBJS_t2) $(LIBS)

wpa_passphrase: $(OBJS_p)
	$(LDO) $(LDFLAGS) -o wpa_passphrase $(OBJS_p) $(LIBS_p)

wpa_cli: $(OBJS_c)
	$(LDO) $(LDFLAGS) -o wpa_cli $(OBJS_c) $(LIBS_c)

win_if_list: win_if_list.c
	$(LDO) $(LDFLAGS) -o $@ win_if_list.c $(CFLAGS) $(LIBS_w)

eap_psk.so: eap_psk.c eap_psk_common.c
	$(CC) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $^ \
		-Deap_peer_psk_register=eap_peer_method_dynamic_init

eap_pax.so: eap_pax.c eap_pax_common.c
	$(CC) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $^ \
		-Deap_peer_pax_register=eap_peer_method_dynamic_init

eap_sake.so: eap_sake.c eap_sake_common.c
	$(CC) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $^ \
		-Deap_peer_sake_register=eap_peer_method_dynamic_init

%.so: %.c
	$(CC) -o $@ $(CFLAGS) -shared -rdynamic -fPIC $< \
		-D$(*:eap_%=eap_peer_%)_register=eap_peer_method_dynamic_init


# parameters for Microsoft Visual C++ Toolkit 2003 compiler
CL=cl
CLDIR=C:\Program Files\Microsoft Visual C++ Toolkit 2003
PSDKDIR=C:\Program Files\Microsoft Platform SDK for Windows XP SP2
CLFLAGS=-O
CLLIBS=wbemuuid.lib libcmt.lib kernel32.lib uuid.lib ole32.lib oleaut32.lib \
	ws2_32.lib

ndis_events: ndis_events.cpp
	INCLUDE="$(CLDIR)\include;$(PSDKDIR)\Include" \
	LIB="$(CLDIR)\lib;$(PSDKDIR)\Lib" \
	$(CL) $(CLFLAGS) -o ndis_events.exe ndis_events.cpp \
		/link -nodefaultlib $(CLLIBS)

wpa_supplicant.exe: wpa_supplicant
	mv -f $< $@
wpa_cli.exe: wpa_cli
	mv -f $< $@
wpa_passphrase.exe: wpa_passphrase
	mv -f $< $@
win_if_list.exe: win_if_list
	mv -f $< $@
eapol_test.exe: eapol_test
	mv -f $< $@

WINALL=wpa_supplicant.exe wpa_cli.exe wpa_passphrase.exe win_if_list.exe

windows-bin: $(WINALL)
	$(STRIP) $(WINALL)

wpa_gui/Makefile:
	qmake -o wpa_gui/Makefile wpa_gui/wpa_gui.pro 

wpa_gui: wpa_gui/Makefile
	$(MAKE) -C wpa_gui

TEST_SRC_MS_FUNCS = ms_funcs.c crypto.c sha1.c md5.c \
	os_unix.c
test-ms_funcs: $(TEST_SRC_MS_FUNCS)
	$(CC) -o test-ms_funcs -Wall -Werror $(TEST_SRC_MS_FUNCS) \
		-DTEST_MAIN_MS_FUNCS -lcrypto -I../hostapd -I.
	./test-ms_funcs
	rm test-ms_funcs

TEST_SRC_SHA1 = sha1.c
test-sha1: $(TEST_SRC_SHA1)
	$(CC) -o test-sha1 -Wall -Werror $(TEST_SRC_SHA1) \
		-DTEST_MAIN -I../hostad -I.
	./test-sha1
	rm test-sha1

TEST_SRC_AES_WRAP = aes_wrap.c
test-aes_wrap: $(TEST_SRC_AES_WRAP)
	$(CC) -o test-aes_wrap -Wall -Werror $(TEST_SRC_AES_WRAP) \
		-DTEST_MAIN -I../hostad -I.
	./test-aes_wrap
	rm test-aes_wrap

TEST_SRC_EAP_SIM_COMMON = eap_sim_common.c sha1.c md5.c \
	aes_wrap.c common.c os_unix.c
test-eap_sim_common: $(TEST_SRC_EAP_SIM_COMMON)
	$(CC) -o test-eap_sim_common -Wall -Werror $(TEST_SRC_EAP_SIM_COMMON) \
		-DTEST_MAIN_EAP_SIM_COMMON -I../hostapd -I.
	./test-eap_sim_common
	rm test-eap_sim_common

tests: test-ms_funcs test-sha1 test-aes_wrap test-eap_sim_common

clean:
	rm -f core *~ *.o *.d eap_*.so $(ALL) $(WINALL)

%.eps: %.fig
	fig2dev -L eps $*.fig $*.eps

%.png: %.fig
	fig2dev -L png -m 3 $*.fig | pngtopnm | pnmscale 0.4 | pnmtopng \
		> $*.png

docs-pics: doc/wpa_supplicant.png doc/wpa_supplicant.eps

docs: docs-pics
	doxygen doc/doxygen.full
	$(MAKE) -C doc/latex
	cp doc/latex/refman.pdf wpa_supplicant-devel.pdf

docs-fast: docs-pics
	doxygen doc/doxygen.fast

clean-docs:
	rm -rf doc/latex doc/html
	rm -f doc/wpa_supplicant.{eps,png} wpa_supplicant-devel.pdf

-include $(OBJS:%.o=%.d)
