CHANGELOG_PATH=$1
RELEASES_FOLDER=.github/releases/
FILES="$RELEASES_FOLDER*"

echo Working on $CHANGELOG_PATH

# for every entry in the releases folder
for file in $(eval echo $FILES)
do
  if [ -f "$file" ]
  then
    echo "Processing $file"
    filename=$(basename -- "$file")
    filename="${filename%.*}"
    # read the file contents
    filecontent=$(cat $file)
    # replace new lines in file contents, so we can pipe it into sed
    replaced_content=$(echo $filecontent | sed '$!s/$/\\n/' | tr -d '\n')
    # add file content after the line with the full changelog link (e.g. [Full Changelog](https://github.com/iotaledger/identity/compare/v0.3.0...v0.5.0-dev.1) of corresponding version 
    # note we use '@' as a delimiter because the content contains '\'
    sed -i "\@\.\.\.$filename@a\ \n$replaced_content" $CHANGELOG_PATH
  else
    echo "Warning: Could not find \"$file\""
  fi
done
echo "Done"