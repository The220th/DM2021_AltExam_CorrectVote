del /s *.class
javac -encoding utf8 -cp .;./lib/CipherLib-Beta_V0.2.jar ./vote/Start.java
java -cp .;./lib/CipherLib-Beta_V0.2.jar vote.Start -V
