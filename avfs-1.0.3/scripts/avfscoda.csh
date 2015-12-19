if ( -f ~/.avfs) then
	if ( ! -f '/#avfs-on' ) then
		true
	endif
else 
	if ( ! -f '/#avfs-off' ) then
		true
	endif
endif

alias avfs-on 'if ( ! -f  /#avfs-on ) echo "avfs turned on"'
alias avfs-off 'if ( ! -f  /#avfs-off ) echo "avfs turned off"'
alias avfs-stat 'if ( -e /#avfsstat ) cat /#avfsstat/copyright'
