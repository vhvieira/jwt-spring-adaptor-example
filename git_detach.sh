#! /usr/bin/env bash
echo "Welcome to GIT detach script"
echo "***Please be aware of the impacts before running***"

declare OUTPUT=`git remote -v `
echo $OUTPUT
if [[ $OUTPUT == *"http"* ]]; then
  echo "It will detach current project"
fi
echo "Do you really run detach process?"
read answer
if [ "$answer" != "${answer#[Yy]}" ] ;then
    echo "Removing current project git links"
    rm -rf .git
    echo "Do you wish to create a new git repo?"
    read answer
    if [ "$answer" != "${answer#[Yy]}" ] ;then
        echo "Creating new repository"
        git init
        echo "Creating initial commit"
        git add README.md
        git commit -m "first commit"
        read answer
        echo "Do you want to link to a new remote repo?"
        if [ "$answer" != "${answer#[Yy]}" ] ;then
            read -p "Remote repo: "  remoterepo
            echo "Remote repo: $remoterepo"
            #git remote add origin $remoterepo
            #git push -u origin master
        else
            echo "Bye. See you!"
        fi 
    else
        echo "Bye Bye!"
    fi 
else
    echo "Safe choice! Bye!"
fi 