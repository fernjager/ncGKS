#!/bin/bash

# User tweakable settings
TIMEOUT=5		 			# How many seconds should elapse before disconnect? POST fails with less than 5
REQUEST_SIZE_LIMIT=64000 	# 64K should be enough for anyone!
SEARCH_TERM_MAX_LENGTH=50	# Limit search term length
SEARCH_TERM_MIN_LENGTH=1    # Minium search term length
GPG_OPTIONS=				# i.e. Use your own keychain w/ GPG_OPTIONS=--homedir /dir/to/customkeychain

# Other constants
VERSION="1.0.0"
HTTP_HEADER="HTTP/1.0 200 OK\n\rServer: ncGKS $VERSION\n\rConnection: close\n\rContent-Type: text/xml; charset=utf-8\n\r\n\r"

# Cleanup, create a named pipe
if [ -f /tmp/ncGKSpipe ]; then rm /tmp/ncGKSpipe; fi
mkfifo /tmp/ncGKSpipe

if [ -f /tmp/ncGKSpre ]; then rm /tmp/ncGKSpre; fi
if [ -f /tmp/ncGKStmp ]; then rm /tmp/ncGKStmp; fi


#### This function converts TRU format output into INFO format

## What we get from `gpg --with-colons --list-public-keys`
# tru::1:1383765142:0:3:1:5
# pub:u:4096:1:176F4BAF951EE9FB:1366856511:::u:::escaESCA:
# uid:u::::1366856511::56F9038F355474992E35767607A7CE4F8BE125C8::Robert Chen <fernjager@gmail.com>:
# sub:u:4096:1:95091D4105924E8F:1366856511::::::esa:

## What we want
# info:1:12
# pub:951EE9FB:1:4096:1366856511::
# uid:Robert Chen <fernjager@gmail.com>:1366856511::

## TODO: Buggy, handle cases where there are multiple uids
function convertTRU2INFO(){
	HEADER="info:1:"
	BODY=""
	TOTALCOUNT=0

	# Read all lines of input
	while read line ; do

		# Split up colon-deliminated fields
		IFS=':' declare -a 'fields=($line)'

		# Parse pubkey lines
		if [[ ${fields[0]} == "pub" ]] ; then

			# Pull out the fields we want
			BITLENGTH=${fields[2]}
			TYPE=${fields[3]}
			HALFKEYHASH=${fields[4]:8:16}
			CONVERTED_DATE=${fields[5]}
		fi

		# Parse uid line
		if [[ ${fields[0]} == "uid" ]] ; then
			EMAIL_STRING=${fields[9]}

			# Build INFO string
			BODY=$BODY"pub:"$HALFKEYHASH:$TYPE:$BITLENGTH:$CONVERTED_DATE::"\n""uid:"$EMAIL_STRING:$CONVERTED_DATE::"\n"
	 		TOTALCOUNT=$((TOTALCOUNT + 1))
		fi

		unset IFS
 	done <<<"$1"

	echo -e "$HEADER$TOTALCOUNT\n$BODY"
}


# Main Loop-de-loop
while true
do
	# Have netcat to listen to incoming requests
	# and pipe the stdout into the unnamed pipe
	# netcat will take into its stdin, anything coming out of fpipe
	nc -w $TIMEOUT -l 11371 < /tmp/ncGKSpipe | (

		# Now, we're inside the unnamed pipe of netcat's stdout
		# Read netcat's output (incoming client request)
		read REQUEST

		# Check the size of the request
		if [[ ${#REQUEST} -gt $REQUEST_SIZE_LIMIT ]] ; then
			echo ""
			continue
		fi

		# Parse request and do what was requested

		##### GPG Client/Web PubKey POST
		if [[ $REQUEST == "POST /pks/add"* ]] ; then

			echo "$HTTP_HEADER"
			echo "
			<html><body><h1>Key processed!</body></html>"
			grep "keytext=" | sed "s/keytext=.*/&/" > /tmp/ncGKSpre

			REQUEST=`cat /tmp/ncGKSpre`

			# Change all url-encoded newlines %0A to tilde
			REQUEST=$(echo $REQUEST | sed "s/\%0A/\~/g")

			# Now urldecode everything else
			printf -v REQUEST "%b" "${REQUEST//%/\x}"
			echo -e $REQUEST > /tmp/ncGKSpre

			# Reconvert tilde to an actual newline, newline in place of keytext
			# Web submissions- spaces turn into +, but we can't replace them all willy-nilly
			# Sed sucks with newlines- hacky method in place:
			# do not tab the line after this one
			sed "s/keytext=/\
/g" /tmp/ncGKSpre\
			| tr "~" "\n"\
			| sed "s/m-urlencoded//g"\
			| sed "s/BEGIN+PGP+PUBLIC+KEY+BLOCK/BEGIN PGP PUBLIC KEY BLOCK/g"\
			| sed "s/END+PGP+PUBLIC+KEY+BLOCK/END PGP PUBLIC KEY BLOCK/g"\
			| sed "s/^.*\:.*$//g" > /tmp/ncGKStmp

			# Import the key
			gpg $GPG_OPTIONS --import /tmp/ncGKStmp

			continue
		fi


		##### GPG Client Raw PubKey Retrieval "/pks/lookup?op=get&search=XXXXX"

		# Look for op=get in the request
		if [[ $REQUEST == *"op=get"* ]] ; then

			# Extract search term, convert urlencoded space to real space, trim
			SEARCH_TERM=`echo "$REQUEST" | sed "s/.*search=\(.*\)/\1/g" \
										 | sed "s/\&.*//g" \
										 | sed "s/ HTTP\/...//g" \
										 | sed "s/%20/ /g"`

			# Check length of search term
			if [[ ${#SEARCH_TERM} -gt SEARCH_TERM_MAX_LENGTH || ${#SEARCH_TERM} -lt SEARCH_TERM_MIN_LENGTH ]] ; then
				echo ""
				continue
			fi

			# Sanitize search term
			SEARCH_TERM=${SEARCH_TERM//[^@.a-zA-Z0-9_ ]/}

			# Export the pubkey of the first match
			SEARCH_RESULT=$(gpg $GPG_OPTIONS --export -a "$SEARCH_TERM")
			echo "$SEARCH_RESULT"
			continue
		fi


		##### GPG Client Raw PubKey Search "/pks/lookup?op=index&options=mr&search=XXXXX"

		# Look for options=mr in the request
		if [[ $REQUEST == *"op=index"* ]] ; then

			# Extract search term, convert urlencoded space to real space, trim
			SEARCH_TERM=`echo "$REQUEST" | sed "s/.*search=\(.*\)/\1/g" \
										 | sed "s/\&.*//g" \
										 | sed "s/ HTTP\/...//g" \
										 | sed "s/%20/ /g"`
			# Check length of search term
			if [[ ${#SEARCH_TERM} -gt SEARCH_TERM_MAX_LENGTH || ${#SEARCH_TERM} -lt SEARCH_TERM_MIN_LENGTH ]] ; then
				echo ""
				continue
			fi

			# Check length of search term, min length denial-of-service attack limited by timeout
			SEARCH_TERM=${SEARCH_TERM//[^@.a-zA-Z0-9_ ]/}

			SEARCH_RESULT=$(gpg $GPG_OPTIONS --with-colons --list-public-keys "$SEARCH_TERM")
			convertTRU2INFO "$SEARCH_RESULT"
			continue
		fi


		##### HTML PubKey Search with Signatures "/pks/lookup?op=vindex&search=robert%20chen"

		# robert@localhost:~/Downloads$ gpg --list-sigs
		# pub   4096R/951EE9FB 2013-04-25
		# uid                  Robert Chen <fernjager@gmail.com>
		# sig 3        951EE9FB 2013-04-25  Robert Chen <fernjager@gmail.com>sub   4096R/05924E8F 2013-04-25
		# sig          951EE9FB 2013-04-25  Robert Chen <fernjager@gmail.com>

		# Look for op=vindex in the request
		if [[ $REQUEST == *"op=vindex"* ]] ; then

			# Extract search term, convert urlencoded space to real space, trim
			SEARCH_TERM=`echo "$REQUEST" | sed "s/.*search=\(.*\)/\1/g" \
										 | sed "s/\&.*//g" \
										 | sed "s/ HTTP\/...//g" \
										 | sed "s/%20/ /g"`

			# Check length of search term
			if [[ ${#SEARCH_TERM} -gt SEARCH_TERM_MAX_LENGTH || ${#SEARCH_TERM} -lt SEARCH_TERM_MIN_LENGTH ]] ; then
				echo ""
				continue
			fi

			# Sanitize search term
			SEARCH_TERM=${SEARCH_TERM//[^@.a-zA-Z0-9_ ]/}

			# Format everything, add ugly link-ending hacks
			SEARCH_RESULT=$(gpg $GPG_OPTIONS --list-sigs "$SEARCH_TERM" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g" | sed "s/uid /<\/a><br><br><b>uid<\/b> /g" | sed "s/pub /<hr><b>pub<\/b>/g" | sed "s/sig .*/<\/a><br>&<\/a>/g" | sed "s/sub /<br><br><b>sub<\/b>/g")

			echo "$HTTP_HEADER

				<html><head><title>Public Key Server</title></head>\
			  <body><h1>Search results for '$SEARCH_TERM'</h1><pre>Type bits/keyID     cr. time   exp time   key expir\
		 	  </pre><pre>"

			# Generate links for hex and name
			echo $SEARCH_RESULT | sed "s/\([A-Z0-9]\{8\}\) \([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\) /<a href=\"\/pks\/lookup?op=get\&search=\1\">\1<\/a> \2 <a href=\"\/pks\/lookup?op=vindex\&search=\1\">/g" | sed "s/ <\/a>/<\/a> /g"
			echo "<hr></pre><br/><br/></body></html>"
			continue
		fi


		##### Default, HTML PubKey Search, single line "/pks/lookup?search=robert%20chen"

		# robert@localhost:~/Downloads$ gpg --list-keys robert
		# pub   4096R/951EE9FB 2013-04-24
		# uid                  Robert Chen <fernjager@gmail.com>
		# sub   4096R/05924E8F 2013-04-25

		# <html><head><title>Search results for 'robert chen'</title></head>
		# <body><h1>Search results for 'robert chen'</h1><pre>Type bits/keyID     Date       User ID
		# </pre><hr><pre>
		# pub  4096R/<a href="/pks/lookup?op=get&search=0x176F4BAF951EE9FB">951EE9FB</a> 2013-04-25 <a href="/pks/lookup?op=vindex&search=0x176F4BAF951EE9FB">Robert Chen &lt;fernjager@gmail.com&gt;</a>
		# </pre><hr><pre>

		if [[ $REQUEST == *"search="* ]] ; then

			# Extract search term, convert urlencoded space to real space, trim
			SEARCH_TERM=`echo "$REQUEST" | sed "s/.*search=\(.*\)/\1/g" \
										 | sed "s/\&.*//g" \
										 | sed "s/ HTTP\/...//g" \
										 | sed "s/%20/ /g"`

			# Check length of search term
			if [[ ${#SEARCH_TERM} -gt SEARCH_TERM_MAX_LENGTH || ${#SEARCH_TERM} -lt SEARCH_TERM_MIN_LENGTH ]] ; then
				echo ""
				continue
			fi

			# Sanitize search term
			SEARCH_TERM=${SEARCH_TERM//[^@.a-zA-Z0-9_ ]/}

			# Replace the first occurrence of uid, get rid of the subkey line, change < and > to html entities
			SEARCH_RESULT=$(gpg $GPG_OPTIONS --list-public-keys "$SEARCH_TERM" | sed "s/uid / /" | sed "s/sub.*//g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g" | sed "s/pub/<hr>&/g" )

			# link ending hack
			SEARCH_RESULT=$(echo $SEARCH_RESULT | sed "s/\&gt;/\&gt;<\/a>/g" )

			echo "$HTTP_HEADER

				  <html><head><title>Public Key Server</title></head>\
				  <body><h1>Search results for '$SEARCH_TERM'</h1><pre>Type bits/keyID     Date       User ID\
			 	  </pre><pre>"

			# Generate links and clean it up
			echo $SEARCH_RESULT | sed "s/\([A-Z0-9]\{8\}\) \([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\) /<a href=\"\/pks\/lookup?op=get\&search=\1\">\1<\/a> \2 <a href=\"\/pks\/lookup?op=vindex\&search=\1\">/g" | sed "s/ <\/a>/<\/a> /g"


			echo "<hr></pre><br/><br/></body></html>"
			continue
		fi

		echo "$HTTP_HEADER

		<html>
		<head><title>Public Key Server</title></head>
		<body>
		<h1>Public Key Server</h1>
		<b>Server Info: </b> This (temporary!) server is running <a href=\"https://github.com/fernjager/ncGKS\">ncGKS</a> written by Robert J Chen.<br>
		<b>Related Info: </b><a href=\"http://www.faqs.org/faqs/pgp-faq/part1/\">Information about PGP</a> </b><a href=\"http://en.wikipedia.org/wiki/Pretty_Good_Privacy\">Wikipedia Entry</a>\
		<hr>
		<h2>Search for a Key</h2>
		<form action=\"/pks/lookup\" method=\"GET\">
			Search String: <input name=\"search\" size=40>
			<input type=\"submit\" value=\"Search!\"> with signatures: <input type=\"checkbox\" name=\"op\" value=\"vindex\"><p>
		</form>
		<hr>

		<h2> <a name=\"submit\">Submit a key</a></h2>
		<form action=\"/pks/add\" method=\"POST\">

		Enter ASCII-armored PGP key here: <p>
		<textarea name=\"keytext\" rows=20 cols=66></textarea><p>

		<input type=\"reset\" value=\"Clear\">
		<input type=\"submit\" value=\"Submit this key to the keyserver!\"><p>

		</form>

		<hr>
		<h2>FAQ</h2>
			<b>How do I add this keyserver?</b><br>
			<i>In ~/.gnupg/config, add \"keyserver hkp://this-server-address\"</i><br><br>

			<b>How do I search for a key from the keyserver from GnuPG?</b><br>
			<i>gpg --search-key &lt;keywords&gt;</i><br><br>

			<b>How do I send a key to the keyserver from GnuPG?</b><br>
			<i>gpg --send-key &lt;951EE9FB&gt;</i><br><br>

			<b>How do I retrieve a key from the keyserver from GnuPG?</b><br>
			<i>gpg --recv-key &lt;951EE9FB&gt;</i><br><br>
		</p>

		</html>
		"

	# Now dump all our echoed data back into the named pipe to netcat's stdin
	) > /tmp/ncGKSpipe
done
