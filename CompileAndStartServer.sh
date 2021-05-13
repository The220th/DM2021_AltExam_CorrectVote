#!/bin/bash
find . -name "*.class" -delete
javac -cp .:./lib/CipherLib-Beta_V0.2.jar ./vote/Counter/CounterHundler.java
java -cp .:./lib/CipherLib-Beta_V0.2.jar vote.Counter.CounterHundler
