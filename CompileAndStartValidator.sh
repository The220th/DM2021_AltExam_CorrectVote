#!/bin/bash
find . -name "*.class" -delete
javac -cp .:./lib/CipherLib-Beta_V0.2.jar ./vote/Validator/ValidatorHundler.java
java -cp .:./lib/CipherLib-Beta_V0.2.jar vote.Validator.ValidatorHundler
