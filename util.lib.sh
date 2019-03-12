ResultHook() {
	local r=$?;
	local hook="$1";shift;
	if [ $r -eq 0 ]; then
		echo >&2 "ok: $*";
	else
		echo >&2 "KO: $*";
	fi
	return $r;
}

directory_needed() {
	[ -d "$1" ] || mkdir -- "$1"
	[ -d "$1" ] || return 1
}
symlink_needed() {
	local basedir="$1" src="$2" dst="$3"; shift 3;
	(       
		cd -- "$basedir" &&
		if [ ! -e "$dst" ]; then
			ln -s "$src" "$dst"
		fi
	)
}

get_or_update_svn() {
	local basedir="$1" url="$2" subdir="$3";shift 3
	if [ -d "$basedir/$subdir" ]; then
		if ${wantupdate:-false}; then
			( cd -- "$basedir/$subdir" && svn update -q; ResultHook svn "svn update -> $basedir/$subdir" )
		fi
	else
		( cd -- "$basedir" && svn checkout -q "$url" "$subdir"; ResultHook svn "svn checkout -> $basedir/$subdir" )
	fi
}
update_git() {
        local basedir="$1" subdir="$2";shift 2
        if ! ${noupdate:-false}; then
                ( cd -- "$basedir/$subdir" && git pull -q; ResultHook git "git pull -> $basedir/$subdir" )
        fi
}
switch_to_branch_git() {
	local br="$1";shift;
	if [ -n "$br" ]; then
		( cd -- "$basedir/$subdir" && git checkout "$br"; ResultHook git "branch $br" ) || return 1
	fi
}

get_or_update_in_branch_git() {
	local basedir="$1" url="$2" subdir="$3";shift 3
	local br=''
	if [ $# -gt 0 ]; then
		br="$1";shift;
	fi
	if [ -d "$basedir/$subdir" ]; then
		if [ -n "$br" ]; then
			switch_to_branch_git "$br" || return 1
		fi
		update_git "$basedir" "$subdir"
	else    
		if [ -n "$br" ]; then
			( cd -- "$basedir" && git clone -q --branch "$br" "$url" "$subdir";  ResultHook git "git clone (branch $br) -> $basedir/$subdir" )
		else    
			( cd -- "$basedir" && git clone -q "$url" "$subdir"; ResultHook git "git clone -> $basedir/$subdir" )
		fi
	fi
}

get_or_update_git() {
	local basedir="$1" url="$2" subdir="$3";shift 3
	if [ $# -gt 0 ]; then
		echo >&2 "Use get_or_update_in_branch_git instead of get_or_update_git"
		return 123
	fi
	if [ ! -d "$basedir/$subdir" ]; then
		( cd -- "$basedir" && git clone -q "$url" "$subdir"; ResultHook git "git clone -> $basedir/$subdir" )
	fi
	if [ -d "$basedir/$subdir" ]; then
		update_git "$basedir" "$subdir"
	fi
}

recursive_auto_setup() {
	local into="$1";shift
	find "$into" -type f -name setup.sh -path '*/targets/*' |
	grep -v '\(obsolete\|\.old/\|/old\.\)' |
	while read -r f; do
		chmod +x "$f"
		echo >&2 "DEBUG: run $f"
		"$f"; ResultHook setup "run $f"
	done
}

config_git() {
	git config "$@";
}

is_on_branch_git() {
	:
}
config_set_git() {
	:
}
config_unset_git() {
	git config --unset "$@";

}
config_unset_all_git() {
	git config --unset-all "$@";
}

branches_git() {
	git branch --pro
}
