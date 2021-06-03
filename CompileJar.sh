#!/bin/bash
find . -name "*.class" -delete
javac -encoding utf8 -cp .:./lib/CipherLib-Beta_V0.2.jar $(find . -name "*.java")
jar cvf0m ./CorrectVote.jar MANIFEST.MF $(find . -name "*.class")
