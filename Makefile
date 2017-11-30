
default: javabuild



javabuild: 
	-mkdir -p bin
	javac -sourcepath src \
          -classpath "lib/*" \
          -d bin \
          src/cloudStorage/*.java    

clean:
	-rm -r bin

