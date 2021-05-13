#!/bin/bash
find . -name "*.class" -delete
javac -Xlint:deprecation -cp .:./lib/CipherLib-Beta_V0.2.jar ./vote/Voter/VoterHundler.java
java -cp .:./lib/CipherLib-Beta_V0.2.jar vote.Voter.VoterHundler
