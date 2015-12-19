SUBDIRS = init

####################
initstyle      = @initstyle@
start_levels   = @start_levels@
stop_levels    = @stop_levels@
start_prio     = @start_prio@
stop_prio      = @stop_prio@
i_rcdir        = $(DESTDIR)/@rcdir@
rcscriptdir    = @rcscriptdir@

i_profiledir   = @profiledir@

absrcscriptdir = $(i_rcdir)/$(rcscriptdir)
startname = S$(start_prio)avfscoda
stopname  = K$(stop_prio)avfscoda

i_overlaydir = $(DESTDIR)/overlay
i_devdir = $(DESTDIR)/dev
i_codadev0 = $(i_devdir)/cfs0
i_codadev1 = $(i_devdir)/cfs1
i_emacsstart = $(sysconfdir)/emacs/site-start.d
#################

EXTRA_DIST = avfscoda.csh avfscoda.sh avfscoda.el davpass ftppass mountavfs umountavfs

bin_SCRIPTS = ftppass davpass @install_scriptcomps@
EXTRA_SCRIPTS = avfs-config

if INSTALL_EMACS
if INSTALL_AVFSCODA
emacsscriptdir = $(i_emacsstart)
emacsscript_SCRIPTS = avfscoda.el
endif
endif

if INSTALL_AVFSCODA_PROFILE
avfscodaprofiledir = $(i_profiledir)
avfscodaprofile_SCRIPTS = avfscoda.csh avfscoda.sh
endif

#if INSTALL_INITSCRIPT
#initscriptdir = $(absrcscriptdir)
#initscript_SCRIPTS = init/avfscoda.@initstyle@
#endif

install-data-local:
if INSTALL_INITSCRIPT
	@$(mkinstalldirs) $(absrcscriptdir)
	$(INSTALL_SCRIPT) $(srcdir)/init/avfscoda.@initstyle@ $(absrcscriptdir)/avfscoda
endif
if INSTALL_SCRIPTLINKS
	@for i in $(start_levels); do \
	  $(mkinstalldirs) $(i_rcdir)/rc$$i.d; \
	  echo Creating start link for runlevel $$i; \
	  rm -f $(i_rcdir)/rc$$i.d/$(startname); \
	  ln -s ../$(rcscriptdir)/avfscoda $(i_rcdir)/rc$$i.d/$(startname); \
	done
	@for i in $(stop_levels); do \
	  $(mkinstalldirs) $(i_rcdir)/rc$$i.d; \
	  echo Creating stop link for runlevel $$i; \
	  rm -f $(i_rcdir)/rc$$i.d/$(stopname); \
	  ln -s ../$(rcscriptdir)/avfscoda $(i_rcdir)/rc$$i.d/$(stopname); \
	done
endif
if INSTALL_CODADEV
	@$(mkinstalldirs) $(i_overlaydir)
	@$(mkinstalldirs) $(i_devdir)
	@if ! test -e $(i_codadev0); then mknod -m 600 $(i_codadev0) c 67 0; fi
	@if ! test -e $(i_codadev1); then mknod -m 600 $(i_codadev1) c 67 1; fi
endif

uninstall-local:
if INSTALL_INITSCRIPT
	rm -f $(absrcscriptdir)/avfscoda
endif
if INSTALL_SCRIPTLINKS
	@for i in $(start_levels); do \
	  rm -f $(i_rcdir)/rc$$i.d/$(startname); \
	done
	@for i in $(stop_levels); do \
	  rm -f $(i_rcdir)/rc$$i.d/$(stopname); \
	done
endif

start:
	$(absrcscriptdir)/avfscoda start
