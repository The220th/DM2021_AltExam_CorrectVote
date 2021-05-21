del /s *.class
javac -encoding utf8 -cp .;./lib/CipherLib-Beta_V0.2.jar ./vote/Validator/ValidatorHundler.java
javac -encoding utf8 -Xlint:deprecation -cp .;./lib/CipherLib-Beta_V0.2.jar ./vote/Common/ObjectConverter.java
javac -encoding utf8 -Xlint:deprecation -cp .;./lib/CipherLib-Beta_V0.2.jar ./vote/Common/Message.java
java -cp .;./lib/CipherLib-Beta_V0.2.jar vote.Validator.ValidatorHundler
