CC = @COMPILER@
DESTDIR = @DESTDIR2@

HEADERDIR = $(DESTDIR)/include
LIBDIR = $(DESTDIR)/libskey
MANDIR = $(DESTDIR)/man
BINDIR = $(DESTDIR)/bin
SBINDIR = $(DESTDIR)/sbin

CFLAGS = @CFLAGS@

LIB     =  libskey.a
LIBOBJS =  skeylogin.o skeysubr.o md4.o put.o debug.o
LIBSRCS =  skeylogin.c skeysubr.c md4.c put.c debug.c

all:  $(LIB) key keyinit keysh done

setuid:
    chmod 777 keyinit keysh

install:  all setuid
	mkdir -p $(HEADERDIR)
	mkdir -p $(LIBDIR)
	mkdir -p $(MANDIR)
	mkdir -p $(BINDIR)
	mkdir -p $(SBINDIR)
	@INSTALLPROGRAM@ key $(BINDIR)
	@INSTALLPROGRAM@ keyinit $(BINDIR)
	@INSTALLPROGRAM@ keysh $(BINDIR)
	@INSTALLPROGRAM@ skeylogin $(SBINDIR)
	@INSTALLPROGRAM@ $(LIB) $(LIBDIR)
	@INSTALLPROGRAM@ *.h $(HEADERDIR)


key:  skey.c
	$(CC) -o $@ $(CFLAGS) skey.c $(LIB) $(SYSLIBS)

keyinit:  skeyinit.c
	$(CC) -o $@ $(CFLAGS) skeyinit.c $(LIB) $(SYSLIBS)

keysh:  skeysh.c
	$(CC) -o $@ $(CFLAGS) skeysh.c $(LIB) $(SYSLIBS)

$(LIB): $(LIBOBJS)
	ar rv $(LIB) $(LIBOBJS)
	$(RANLIB) $(LIB)

done:
	@echo "Make completed."

clean:
	rm -f key keyinit keysh *.o libskey.a *.bak *.BAK *.s tags
