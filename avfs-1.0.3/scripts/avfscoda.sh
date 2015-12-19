if [ -f ~/.avfs ]; then
	if [ ! -f '/#avfs-on' ]; then 
		true
	fi
else 
	if [ ! -f '/#avfs-off' ]; then
		true
	fi
fi

alias avfs-on='if [ ! -f /#avfs-on ]; then echo "avfs turned on"; fi'
alias avfs-off='if [ ! -f /#avfs-off ]; then echo "avfs turned off"; fi'
alias avfs-stat='if [ -e /#avfsstat ]; then cat /#avfsstat/copyright; fi'
