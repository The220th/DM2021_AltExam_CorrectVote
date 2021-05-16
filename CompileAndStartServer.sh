#!/bin/bash
find . -name "*.class" -delete
javac -Xlint:unchecked -cp .:./lib/CipherLib-Beta_V0.2.jar ./vote/Counter/CounterHundler.java
java -cp .:./lib/CipherLib-Beta_V0.2.jar vote.Counter.CounterHundler
